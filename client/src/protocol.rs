//! Wire format and end-to-end encryption.
//!
//! Datagram layout (the relay server never parses any of this):
//!
//! ```text
//! hello: [ 0x01 | sender_id: u32 BE ]                       (plaintext keepalive)
//! audio: [ 0x02 | sender_id: u32 BE | seq: u64 BE | ciphertext ]
//! ```
//!
//! The ciphertext is ChaCha20-Poly1305 over one Opus frame, with the 13-byte
//! header as associated data, so a tampered header fails authentication.
//! The nonce is `sender_id || seq` — unique per key as long as each client
//! picks a random `sender_id` and never reuses a sequence number.

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};

pub const PKT_HELLO: u8 = 0x01;
pub const PKT_AUDIO: u8 = 0x02;
pub const HDR_LEN: usize = 1 + 4 + 8;

/// Derive the 32-byte call key from the shared secret. Both clients must use
/// the same secret; the server never sees it. (A plain hash is fine for a
/// trial — a real deployment would do an authenticated key exchange instead.)
pub fn derive_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"rust-rtc-trial-v1");
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    fn nonce(sender_id: u32, seq: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&sender_id.to_be_bytes());
        n[4..].copy_from_slice(&seq.to_be_bytes());
        Nonce::from(n)
    }

    /// Build an encrypted audio datagram from one Opus frame.
    pub fn seal_audio(&self, sender_id: u32, seq: u64, opus_frame: &[u8]) -> Result<Vec<u8>> {
        let mut pkt = Vec::with_capacity(HDR_LEN + opus_frame.len() + 16);
        pkt.push(PKT_AUDIO);
        pkt.extend_from_slice(&sender_id.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        let ciphertext = self
            .cipher
            .encrypt(
                &Self::nonce(sender_id, seq),
                Payload {
                    msg: opus_frame,
                    aad: &pkt[..HDR_LEN],
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        pkt.extend_from_slice(&ciphertext);
        Ok(pkt)
    }

    /// Parse and decrypt an audio datagram. Returns `(sender_id, seq, opus_frame)`.
    pub fn open_audio(&self, pkt: &[u8]) -> Result<(u32, u64, Vec<u8>)> {
        if pkt.len() <= HDR_LEN || pkt[0] != PKT_AUDIO {
            return Err(anyhow!("not an audio packet"));
        }
        let sender_id = u32::from_be_bytes(pkt[1..5].try_into().unwrap());
        let seq = u64::from_be_bytes(pkt[5..13].try_into().unwrap());
        let plaintext = self
            .cipher
            .decrypt(
                &Self::nonce(sender_id, seq),
                Payload {
                    msg: &pkt[HDR_LEN..],
                    aad: &pkt[..HDR_LEN],
                },
            )
            .map_err(|_| anyhow!("decryption failed (wrong secret or corrupted packet)"))?;
        Ok((sender_id, seq, plaintext))
    }
}

pub fn hello_packet(sender_id: u32) -> [u8; 5] {
    let mut pkt = [0u8; 5];
    pkt[0] = PKT_HELLO;
    pkt[1..].copy_from_slice(&sender_id.to_be_bytes());
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let crypto = Crypto::new(&derive_key("test secret"));
        let frame = [7u8; 160];
        let pkt = crypto.seal_audio(0xDEADBEEF, 42, &frame).unwrap();
        assert_eq!(pkt[0], PKT_AUDIO);
        let (sender, seq, plain) = crypto.open_audio(&pkt).unwrap();
        assert_eq!(sender, 0xDEADBEEF);
        assert_eq!(seq, 42);
        assert_eq!(plain, frame);
    }

    #[test]
    fn wrong_secret_fails() {
        let a = Crypto::new(&derive_key("secret A"));
        let b = Crypto::new(&derive_key("secret B"));
        let pkt = a.seal_audio(1, 1, &[1, 2, 3]).unwrap();
        assert!(b.open_audio(&pkt).is_err());
    }

    #[test]
    fn tampered_header_fails() {
        let crypto = Crypto::new(&derive_key("test secret"));
        let mut pkt = crypto.seal_audio(1, 7, &[9u8; 40]).unwrap();
        pkt[12] ^= 0xFF; // flip a bit in the seq field
        assert!(crypto.open_audio(&pkt).is_err());
    }
}
