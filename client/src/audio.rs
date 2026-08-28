//! Audio capture/playback via cpal, plus a small linear resampler.
//!
//! Devices run at whatever their default config says (rate, channels, sample
//! format); everything is converted to/from the call format — 48 kHz mono —
//! in the send/receive threads, not in the realtime callbacks.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Device, FromSample, Sample, SizedSample};

/// Mono samples shared between the network receive thread (producer) and the
/// playback callback (consumer), already resampled to the output device rate.
pub type PlaybackBuffer = Arc<Mutex<VecDeque<f32>>>;

pub fn list_devices() -> Result<()> {
    let host = cpal::default_host();
    println!("input devices:");
    for dev in host.input_devices()? {
        println!("  {}", dev.name().unwrap_or_else(|_| "<unknown>".into()));
    }
    println!("output devices:");
    for dev in host.output_devices()? {
        println!("  {}", dev.name().unwrap_or_else(|_| "<unknown>".into()));
    }
    Ok(())
}

fn pick_device(
    devices: impl Iterator<Item = Device>,
    default: Option<Device>,
    name: Option<&str>,
    kind: &str,
) -> Result<Device> {
    match name {
        Some(name) => {
            for dev in devices {
                if dev.name().map(|n| n.contains(name)).unwrap_or(false) {
                    return Ok(dev);
                }
            }
            Err(anyhow!("no {kind} device matching {name:?} (try --list-devices)"))
        }
        None => default.ok_or_else(|| anyhow!("no default {kind} device")),
    }
}

/// Start capturing the mic. Mono f32 chunks at the device's native rate are
/// pushed into `tx`. Returns the stream (keep it alive) and the capture rate.
pub fn start_input(name: Option<&str>, tx: mpsc::Sender<Vec<f32>>) -> Result<(cpal::Stream, u32)> {
    let host = cpal::default_host();
    let device = pick_device(
        host.input_devices()?,
        host.default_input_device(),
        name,
        "input",
    )?;
    let config = device
        .default_input_config()
        .context("no default input config")?;
    println!(
        "mic: {} ({} Hz, {} ch, {:?})",
        device.name().unwrap_or_default(),
        config.sample_rate().0,
        config.channels(),
        config.sample_format()
    );
    let rate = config.sample_rate().0;
    let channels = config.channels() as usize;
    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => build_input::<f32>(&device, &config.into(), channels, tx)?,
        cpal::SampleFormat::I16 => build_input::<i16>(&device, &config.into(), channels, tx)?,
        cpal::SampleFormat::U16 => build_input::<u16>(&device, &config.into(), channels, tx)?,
        other => return Err(anyhow!("unsupported input sample format {other:?}")),
    };
    stream.play()?;
    Ok((stream, rate))
}

fn build_input<T>(
    device: &Device,
    config: &cpal::StreamConfig,
    channels: usize,
    tx: mpsc::Sender<Vec<f32>>,
) -> Result<cpal::Stream>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    let stream = device.build_input_stream(
        config,
        move |data: &[T], _| {
            let mono: Vec<f32> = data
                .chunks(channels)
                .map(|frame| {
                    frame.iter().map(|&s| f32::from_sample(s)).sum::<f32>() / channels as f32
                })
                .collect();
            let _ = tx.send(mono);
        },
        |e| eprintln!("input stream error: {e}"),
        None,
    )?;
    Ok(stream)
}

/// Start playback. The callback drains mono samples from `buffer` (must
/// already be at the device rate) and fans them out to every channel.
/// Returns the stream (keep it alive) and the playback rate.
pub fn start_output(name: Option<&str>, buffer: PlaybackBuffer) -> Result<(cpal::Stream, u32)> {
    let host = cpal::default_host();
    let device = pick_device(
        host.output_devices()?,
        host.default_output_device(),
        name,
        "output",
    )?;
    let config = device
        .default_output_config()
        .context("no default output config")?;
    println!(
        "speaker: {} ({} Hz, {} ch, {:?})",
        device.name().unwrap_or_default(),
        config.sample_rate().0,
        config.channels(),
        config.sample_format()
    );
    let rate = config.sample_rate().0;
    let channels = config.channels() as usize;
    // Don't start draining until ~60 ms is buffered, so playback doesn't
    // stutter on the very first packets.
    let prebuffer = rate as usize * 60 / 1000;
    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => {
            build_output::<f32>(&device, &config.into(), channels, prebuffer, buffer)?
        }
        cpal::SampleFormat::I16 => {
            build_output::<i16>(&device, &config.into(), channels, prebuffer, buffer)?
        }
        cpal::SampleFormat::U16 => {
            build_output::<u16>(&device, &config.into(), channels, prebuffer, buffer)?
        }
        other => return Err(anyhow!("unsupported output sample format {other:?}")),
    };
    stream.play()?;
    Ok((stream, rate))
}

fn build_output<T>(
    device: &Device,
    config: &cpal::StreamConfig,
    channels: usize,
    prebuffer: usize,
    buffer: PlaybackBuffer,
) -> Result<cpal::Stream>
where
    T: SizedSample + FromSample<f32>,
{
    let mut started = false;
    let stream = device.build_output_stream(
        config,
        move |data: &mut [T], _| {
            let mut queue = buffer.lock().unwrap();
            if !started && queue.len() >= prebuffer {
                started = true;
            }
            if started && queue.is_empty() {
                started = false; // underrun: rebuild the prebuffer
            }
            for frame in data.chunks_mut(channels) {
                let sample = if started { queue.pop_front().unwrap_or(0.0) } else { 0.0 };
                let value = T::from_sample(sample);
                for out in frame {
                    *out = value;
                }
            }
        },
        |e| eprintln!("output stream error: {e}"),
        None,
    )?;
    Ok(stream)
}

/// Streaming linear-interpolation resampler. Crude but fine for voice.
pub struct Resampler {
    step: f64,
    pos: f64,
    buf: Vec<f32>,
}

impl Resampler {
    pub fn new(src_rate: u32, dst_rate: u32) -> Self {
        Self {
            step: src_rate as f64 / dst_rate as f64,
            pos: 0.0,
            buf: Vec::new(),
        }
    }

    /// Feed source samples; converted samples are appended to `out`.
    pub fn process(&mut self, input: &[f32], out: &mut Vec<f32>) {
        self.buf.extend_from_slice(input);
        while (self.pos as usize) + 1 < self.buf.len() {
            let i = self.pos as usize;
            let frac = (self.pos - i as f64) as f32;
            out.push(self.buf[i] * (1.0 - frac) + self.buf[i + 1] * frac);
            self.pos += self.step;
        }
        let consumed = (self.pos as usize).min(self.buf.len());
        self.buf.drain(..consumed);
        self.pos -= consumed as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resampler_identity() {
        let mut r = Resampler::new(48000, 48000);
        let mut out = Vec::new();
        r.process(&[0.0, 0.25, 0.5, 0.75, 1.0], &mut out);
        // one sample is held back for interpolation; the rest pass through
        assert_eq!(out, vec![0.0, 0.25, 0.5, 0.75]);
    }

    #[test]
    fn resampler_ratio() {
        let mut r = Resampler::new(44100, 48000);
        let input = vec![0.5f32; 44100];
        let mut out = Vec::new();
        r.process(&input, &mut out);
        let expected = 48000usize;
        assert!(
            (out.len() as i64 - expected as i64).unsigned_abs() < 10,
            "expected ~{expected} samples, got {}",
            out.len()
        );
        assert!(out.iter().all(|&s| (s - 0.5).abs() < 1e-6));
    }
}
