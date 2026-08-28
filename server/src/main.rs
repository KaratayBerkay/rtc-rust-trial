//! Relay server: forwards UDP datagrams between connected peers.
//!
//! The server is deliberately protocol-agnostic — it never parses payloads
//! and never holds the encryption key, so it only ever sees ciphertext.
//! Any datagram from an address registers (or refreshes) that peer; the
//! datagram is then forwarded to every other live peer.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;

/// Peers that have been silent this long are dropped.
const PEER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(about = "Encrypted-audio relay: forwards opaque UDP datagrams between peers")]
struct Args {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:4433")]
    listen: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let socket = UdpSocket::bind(&args.listen)
        .with_context(|| format!("failed to bind {}", args.listen))?;
    println!("relay listening on {}", socket.local_addr()?);

    let mut peers: HashMap<SocketAddr, Instant> = HashMap::new();
    let mut buf = [0u8; 2048];

    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recv error: {e}");
                continue;
            }
        };
        let now = Instant::now();

        if peers.insert(src, now).is_none() {
            println!("peer joined: {src} ({} connected)", peers.len());
        }
        peers.retain(|addr, last_seen| {
            let alive = now.duration_since(*last_seen) < PEER_TIMEOUT;
            if !alive {
                println!("peer timed out: {addr}");
            }
            alive
        });

        for addr in peers.keys() {
            if *addr != src {
                if let Err(e) = socket.send_to(&buf[..len], addr) {
                    eprintln!("send to {addr} failed: {e}");
                }
            }
        }
    }
}
