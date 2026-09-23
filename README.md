# FM Aero Code 2

**Fast Memory optical storage.** Encode any file into a printable black-and-white pattern that survives camera capture.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.8.3-brightgreen)]()

---

## What it does

FM Aero Code converts arbitrary bytes into a spectral pattern:

```
file bytes
  -> AeroPack v20 (BWT + MTF + RLE + DPCM adaptive)
  -> AeroSeal v1/v2 (XChaCha20-Poly1305 + Argon2id, optional)
  -> Reed-Solomon RS(255, 223) FEC
  -> PRNG bit interleaving
  -> QPSK onto 128x128 FFT grid (Hermitian symmetric)
  -> 2D IFFT -> grayscale image
  -> PNG (single) or APNG (multi-page)
```

Decoder reverses the pipeline: FFT -> pilot-ring rotation detect -> QPSK -> de-interleave -> RS decode -> decrypt -> unpack.

## Features

- **Any file type**: text, music, photos, video, executables, archives
- **Bit-perfect round-trip**: verified by 9/9 self-tests + 10,000 property-based tests
- **Configurable resilience**: 5 levels from 0% to 50% page-loss recovery
- **Cross-platform**: native GUI (Windows/Linux/macOS) + WASM (browser)
- **Offline**: pure local, no network required
- **Spectral camouflage**: optional logo overlay in low frequencies

## Quick start

Build native:

```bash
cargo build --release
./target/release/fm_gui    # GUI
./target/release/fm_selftest   # verify all round-trips
```

Build WASM (browser):

```bash
wasm-pack build --target web --out-dir web/pkg --no-default-features --features wasm
cd web && python -m http.server 8080
```

## CLI

```bash
# Encode single-page
fm_encode photo.jpg photo.aero.png --password mypass

# Encode with 25% resilience (recover up to 50 lost pages per group)
fm_split book.pdf ./pages --resilience 3

# Decode
fm_decode photo.aero.png restored.jpg --password mypass

# Batch process folders
fm_batch encode ./in ./out --password mypass --recursive --jobs 8

# Generate keypair
fm_keygen write
```

## Project structure

```
src/
  lib.rs                - crate root
  error.rs              - error types
  types.rs              - AeroHeader, DataType, ResilienceLevel
  fec.rs                - Reed-Solomon wrapper
  resilience.rs         - page-level RS (multi-level)
  selftest.rs           - round-trip verification
  crypto/               - AeroSeal v1/v2, Argon2id, Ed25519
  encoder/              - AeroPack, AeroGlint FFT encoder
  decoder/              - FFT decoder, QPSK, pilot detection
  app.rs                - egui GUI
  icon.rs               - application icon
  wasm.rs               - WASM bindings
  bin/                  - CLI tools
web/
  index.html            - scanner + encoder UI
  print.html            - print pages to A4
  sw.js                 - service worker (offline)
  manifest.json         - PWA manifest
tests/
  property_tests.rs     - proptest (10,000 cases)
benches/
  aeropack_bench.rs     - criterion benchmarks
```

## Security

- Argon2id (32 MiB, t=3, p=2) - same parameters on all platforms
- XChaCha20-Poly1305 (24-byte nonce) - encrypt-then-MAC
- HMAC-SHA256 for header + payload integrity
- Ed25519 optional signatures
- `zeroize` scrubbing of key material
- `#![forbid(unsafe_code)]`

See [SECURITY.md](SECURITY.md) for threat model.

## Resilience levels

| Level | Data/Parity | Recovery | Size overhead |
|-------|-------------|----------|---------------|
| Off   | 200/0       | 0%       | +0%           |
| Low   | 190/10      | 5%       | +5%           |
| Balanced | 180/20   | 10%      | +11%          |
| High  | 150/50      | 25%      | +33%          |
| Extreme | 100/100   | 50%      | +100%         |

## License

MIT. See [LICENSE](LICENSE).

---

Author: Maksym Skorina