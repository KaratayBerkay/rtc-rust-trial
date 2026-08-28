# rust-rtc-trial

End-to-end encrypted audio call trial in Rust: two full-duplex clients exchange
mic audio through a relay server that only ever sees ciphertext.

```text
client A  ⇄  relay server  ⇄  client B
mic/speaker    (no key —       mic/speaker
               forwards
               opaque UDP)
```

## How it works

- **Capture/playback**: `cpal` at each device's native rate; converted to the
  call format (48 kHz mono) with a small linear resampler.
- **Mic cleanup**: WebRTC's Audio Processing Module — acoustic echo
  cancellation (the receive path feeds decoded far-end audio to the AEC as
  its speaker reference), noise suppression, adaptive gain, and a high-pass
  filter. Disable with `--no-processing` to A/B against the raw mic.
- **Codec**: Opus, 20 ms frames, VoIP mode (~4 KB/s per direction).
- **Encryption**: ChaCha20-Poly1305 per frame, key = SHA-256 of the shared
  `--secret`. The 13-byte packet header (type, sender id, sequence) is
  authenticated as associated data; the nonce is `sender_id ‖ seq`, so
  duplicates/replays are dropped by sequence tracking on the receiver.
- **Server**: a dumb UDP relay. Any datagram registers its source address as a
  peer and is forwarded to every other live peer (10 s inactivity timeout).
  It never parses payloads and cannot decrypt them.

## Build

Native deps (Debian/Ubuntu): `libasound2-dev` and `pkg-config` for cpal,
`cmake` **or** `libopus-dev` for the Opus crate, and
`libwebrtc-audio-processing-dev` plus `clang` for the audio cleanup:

```sh
sudo apt install libasound2-dev pkg-config cmake libwebrtc-audio-processing-dev clang
```

```sh
cargo build --release
```

## Run

Server (any host both clients can reach):

```sh
cargo run --release -p server -- --listen 0.0.0.0:4433
```

Client on each machine, with the same secret:

```sh
cargo run --release -p client -- --server <server-ip>:4433 --secret "something shared"
```

Useful flags:

- `--list-devices` — show capture/playback device names
- `--input-device <substr>` / `--output-device <substr>` — pick devices by
  name substring (default: system defaults)
- `--no-send` — receive-only client (no mic needed)
- `--no-processing` — send the raw mic (no AEC/noise suppression/AGC)

A wrong `--secret` shows up as `dropping packet: decryption failed` on the
receiver — a handy way to verify the encryption is real.

## Trial-scope caveats

This is a test bed, not a production call stack:

- The pre-shared secret + SHA-256 stands in for a real authenticated key
  exchange (Noise, MLS, DTLS-SRTP…), and there is no forward secrecy.
- Packet loss plays as silence — no Opus PLC/FEC, no adaptive jitter buffer
  (fixed ~60 ms prebuffer, 500 ms latency cap).
- The relay forwards to everyone in its single implicit room; there are no
  room IDs or peer authentication at the relay.
