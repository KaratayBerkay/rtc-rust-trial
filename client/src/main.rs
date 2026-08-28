//! Encrypted audio call client.
//!
//! Pipeline (both directions run at once — full duplex):
//!
//! ```text
//! mic ──cpal──▶ mono f32 ──resample──▶ 48 kHz i16 ──Opus──▶ encrypt ──UDP──▶ relay
//! relay ──UDP──▶ decrypt ──Opus──▶ 48 kHz i16 ──resample──▶ playback buffer ──cpal──▶ speaker
//! ```
//!
//! The relay only ever sees ciphertext; the key is derived from `--secret`,
//! which both clients must share out of band.
//!
//! Mic cleanup runs through WebRTC's Audio Processing Module (APM): acoustic
//! echo cancellation, noise suppression, auto gain, and a high-pass filter.
//! The APM needs to know what the speaker is playing to subtract its echo
//! from the mic, so the receive path feeds decoded far-end audio to it as
//! "render" frames before handing it to playback.

mod audio;
mod protocol;

use std::collections::{HashMap, VecDeque};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use rand::Rng;

use protocol::{Crypto, PKT_AUDIO};

/// The call always runs at 48 kHz mono; device rates are resampled to match.
const CALL_RATE: u32 = 48000;
/// 20 ms Opus frames.
const FRAME_SAMPLES: usize = (CALL_RATE as usize) * 20 / 1000;
/// The WebRTC APM processes fixed 10 ms frames.
const APM_FRAME: usize = (CALL_RATE as usize) * 10 / 1000;
/// Playback latency bound: if the jitter buffer grows past this, drop the
/// oldest audio instead of drifting ever further behind.
const MAX_BUFFER_MS: usize = 500;

#[derive(Parser)]
#[command(about = "End-to-end encrypted audio call client (full duplex)")]
struct Args {
    /// Relay server address, e.g. 192.168.1.10:4433
    #[arg(long, required_unless_present = "list_devices")]
    server: Option<String>,
    /// Shared secret — must match on both clients; never sent to the server
    #[arg(long, required_unless_present = "list_devices")]
    secret: Option<String>,
    /// Substring of the capture device name (default: system default mic)
    #[arg(long)]
    input_device: Option<String>,
    /// Substring of the playback device name (default: system default output)
    #[arg(long)]
    output_device: Option<String>,
    /// List audio devices and exit
    #[arg(long)]
    list_devices: bool,
    /// Receive-only: don't capture or send the mic
    #[arg(long)]
    no_send: bool,
    /// Send the raw mic signal: disable echo cancellation, noise
    /// suppression, auto gain, and the high-pass filter
    #[arg(long)]
    no_processing: bool,
}

/// Set up the WebRTC APM: echo cancellation (delay-agnostic, since our
/// jitter buffer + device latency is unknown), noise suppression, adaptive
/// digital gain, and a high-pass filter against rumble/hum.
fn create_apm() -> Result<webrtc_audio_processing::Processor> {
    use webrtc_audio_processing::*;
    let mut processor = Processor::new(&InitializationConfig {
        num_capture_channels: 1,
        num_render_channels: 1,
        ..InitializationConfig::default()
    })
    .map_err(|e| anyhow::anyhow!("failed to init WebRTC audio processing: {e:?}"))?;
    processor.set_config(Config {
        echo_cancellation: Some(EchoCancellation {
            suppression_level: EchoCancellationSuppressionLevel::High,
            stream_delay_ms: None,
            enable_delay_agnostic: true,
            enable_extended_filter: true,
        }),
        noise_suppression: Some(NoiseSuppression {
            suppression_level: NoiseSuppressionLevel::High,
        }),
        gain_control: Some(GainControl {
            mode: GainControlMode::AdaptiveDigital,
            target_level_dbfs: 3,
            compression_gain_db: 9,
            enable_limiter: true,
        }),
        enable_high_pass_filter: true,
        ..Config::default()
    });
    Ok(processor)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.list_devices {
        return audio::list_devices();
    }
    let server = args.server.expect("clap enforces --server");
    let secret = args.secret.expect("clap enforces --secret");

    let crypto = Arc::new(Crypto::new(&protocol::derive_key(&secret)));
    let my_id: u32 = rand::thread_rng().gen();

    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind UDP socket")?;
    socket
        .connect(&server)
        .with_context(|| format!("cannot resolve server address {server}"))?;
    println!("client id {my_id:08x}, server {server}");

    let sent = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));

    // APM is only needed when we capture a mic; without capture there is no
    // echo to cancel. `Processor` is internally shared, so the clone in the
    // receive thread feeds the same AEC the send thread cleans with.
    let apm = if args.no_send || args.no_processing {
        if !args.no_send {
            println!("audio processing disabled (--no-processing): sending raw mic");
        }
        None
    } else {
        println!("audio processing on: echo cancellation, noise suppression, auto gain");
        Some(create_apm()?)
    };

    // ---- receive path: relay -> decrypt -> Opus decode -> speaker ----
    let playback: audio::PlaybackBuffer = Arc::new(Mutex::new(VecDeque::new()));
    let (_out_stream, out_rate) =
        audio::start_output(args.output_device.as_deref(), Arc::clone(&playback))?;
    {
        let socket = socket.try_clone()?;
        let crypto = Arc::clone(&crypto);
        let received = Arc::clone(&received);
        let apm = apm.clone();
        std::thread::spawn(move || {
            if let Err(e) = recv_loop(socket, crypto, my_id, playback, out_rate, received, apm) {
                eprintln!("receive loop failed: {e:#}");
                std::process::exit(1);
            }
        });
    }

    // ---- send path: mic -> Opus encode -> encrypt -> relay ----
    if args.no_send {
        println!("mic muted (--no-send), listening only");
        let socket = socket.try_clone()?;
        std::thread::spawn(move || loop {
            let _ = socket.send(&protocol::hello_packet(my_id));
            std::thread::sleep(Duration::from_secs(1));
        });
        // keep _out_stream alive on this thread
        stats_loop(&sent, &received);
    }

    let (pcm_tx, pcm_rx) = mpsc::channel::<Vec<f32>>();
    let (_in_stream, in_rate) = audio::start_input(args.input_device.as_deref(), pcm_tx)?;
    {
        let socket = socket.try_clone()?;
        let crypto = Arc::clone(&crypto);
        let sent = Arc::clone(&sent);
        std::thread::spawn(move || {
            if let Err(e) = send_loop(socket, crypto, my_id, pcm_rx, in_rate, sent, apm) {
                eprintln!("send loop failed: {e:#}");
                std::process::exit(1);
            }
        });
    }

    println!("call running — Ctrl-C to hang up");
    stats_loop(&sent, &received);
}

fn stats_loop(sent: &AtomicU64, received: &AtomicU64) -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(5));
        println!(
            "tx {} pkts, rx {} pkts",
            sent.load(Ordering::Relaxed),
            received.load(Ordering::Relaxed)
        );
    }
}

fn send_loop(
    socket: UdpSocket,
    crypto: Arc<Crypto>,
    my_id: u32,
    pcm_rx: mpsc::Receiver<Vec<f32>>,
    in_rate: u32,
    sent: Arc<AtomicU64>,
    mut apm: Option<webrtc_audio_processing::Processor>,
) -> Result<()> {
    let mut encoder = opus::Encoder::new(CALL_RATE, opus::Channels::Mono, opus::Application::Voip)
        .context("failed to create Opus encoder")?;
    let mut resampler = audio::Resampler::new(in_rate, CALL_RATE);
    let mut pending: Vec<f32> = Vec::with_capacity(FRAME_SAMPLES * 4);
    let mut cleaned: Vec<f32> = Vec::with_capacity(FRAME_SAMPLES * 4);
    let mut apm_frame = [0f32; APM_FRAME];
    let mut frame = [0i16; FRAME_SAMPLES];
    let mut opus_buf = [0u8; 2000];
    let mut seq: u64 = 0;
    let mut last_hello = Instant::now();
    // hello keepalives let the relay learn our address (and keep NAT open)
    socket.send(&protocol::hello_packet(my_id))?;

    loop {
        match pcm_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(chunk) => resampler.process(&chunk, &mut pending),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()), // capture stream gone
        }
        if last_hello.elapsed() >= Duration::from_secs(1) {
            let _ = socket.send(&protocol::hello_packet(my_id));
            last_hello = Instant::now();
        }
        // clean the mic in the APM's 10 ms blocks (AEC + NS + AGC run here)
        let mut offset = 0;
        while pending.len() - offset >= APM_FRAME {
            let block = &pending[offset..offset + APM_FRAME];
            match &mut apm {
                Some(apm) => {
                    apm_frame.copy_from_slice(block);
                    apm.process_capture_frame(&mut apm_frame)
                        .map_err(|e| anyhow::anyhow!("APM capture failed: {e:?}"))?;
                    cleaned.extend_from_slice(&apm_frame);
                }
                None => cleaned.extend_from_slice(block),
            }
            offset += APM_FRAME;
        }
        pending.drain(..offset);

        // encode and ship complete 20 ms Opus frames
        let mut offset = 0;
        while cleaned.len() - offset >= FRAME_SAMPLES {
            for (dst, &src) in frame.iter_mut().zip(&cleaned[offset..offset + FRAME_SAMPLES]) {
                *dst = (src.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
            }
            offset += FRAME_SAMPLES;
            let len = encoder.encode(&frame, &mut opus_buf)?;
            let pkt = crypto.seal_audio(my_id, seq, &opus_buf[..len])?;
            seq += 1;
            if let Err(e) = socket.send(&pkt) {
                eprintln!("send failed: {e}");
            } else {
                sent.fetch_add(1, Ordering::Relaxed);
            }
        }
        cleaned.drain(..offset);
    }
}

fn recv_loop(
    socket: UdpSocket,
    crypto: Arc<Crypto>,
    my_id: u32,
    playback: audio::PlaybackBuffer,
    out_rate: u32,
    received: Arc<AtomicU64>,
    mut apm: Option<webrtc_audio_processing::Processor>,
) -> Result<()> {
    let mut decoder = opus::Decoder::new(CALL_RATE, opus::Channels::Mono)
        .context("failed to create Opus decoder")?;
    let mut resampler = audio::Resampler::new(CALL_RATE, out_rate);
    let mut pcm = [0i16; FRAME_SAMPLES * 6];
    let mut resampled = Vec::with_capacity(FRAME_SAMPLES * 2);
    let mut last_seq: HashMap<u32, u64> = HashMap::new();
    let max_buffer = out_rate as usize * MAX_BUFFER_MS / 1000;
    let mut buf = [0u8; 2048];

    loop {
        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(e) => {
                eprintln!("recv error: {e}");
                continue;
            }
        };
        let pkt = &buf[..len];
        if pkt.first() != Some(&PKT_AUDIO) {
            continue; // hello keepalive from the other peer
        }
        let (sender, seq, opus_frame) = match crypto.open_audio(pkt) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("dropping packet: {e}");
                continue;
            }
        };
        if sender == my_id {
            continue;
        }
        // drop duplicates and late reordered packets (also blocks replays)
        match last_seq.get(&sender) {
            Some(&last) if seq <= last => continue,
            _ => {}
        }
        last_seq.insert(sender, seq);
        received.fetch_add(1, Ordering::Relaxed);

        let n = match decoder.decode(&opus_frame, &mut pcm, false) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Opus decode failed: {e}");
                continue;
            }
        };
        resampled.clear();
        let mut as_f32: Vec<f32> =
            pcm[..n].iter().map(|&s| s as f32 / i16::MAX as f32).collect();
        // give the AEC its echo reference: this is exactly what we are about
        // to queue for the speaker (decoded 20 ms = two 10 ms APM blocks)
        if let Some(apm) = &mut apm {
            for block in as_f32.chunks_exact_mut(APM_FRAME) {
                if let Err(e) = apm.process_render_frame(block) {
                    eprintln!("APM render failed: {e:?}");
                }
            }
        }
        resampler.process(&as_f32, &mut resampled);

        let mut queue = playback.lock().unwrap();
        queue.extend(resampled.iter().copied());
        if queue.len() > max_buffer {
            let excess = queue.len() - max_buffer / 2;
            queue.drain(..excess);
        }
    }
}
