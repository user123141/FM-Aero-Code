# FM Aero Code 2

Fast Memory optical storage. Encode any file into a printable black-and-white pattern that survives camera capture.

Version 3.1.0 | MIT License | Author: Maksym Skorina

## What it does

FM Aero Code converts arbitrary bytes into a spectral pattern. Pipeline:

    file bytes
      -> AeroPack v20 (BWT + MTF + RLE + DPCM3 + BCJ x86)
      -> AeroSeal v1/v2 (XChaCha20-Poly1305 + Argon2id, optional)
      -> Reed-Solomon RS(255, 223) FEC
      -> Optional page-level RS resilience (5 levels, 0-50%)
      -> PRNG bit interleaving (SplitMix64)
      -> QPSK onto 128x128 FFT grid (Hermitian symmetric)
      -> Optional photo in low-frequency cells (spectral camouflage)
      -> 2D IFFT -> grayscale image
      -> PNG (single) or APNG (multi-page)

Decoder reverses: strip border -> FFT -> pilot-ring rotation -> QPSK demod
(multipass threshold) -> de-interleave -> RS decode -> decrypt -> unpack.

## Features

- Any file type: text, music, photos, video, executables, archives
- Bit-perfect round-trip: 9/9 self-tests + property-based tests
- Configurable resilience: 0% / 5% / 10% / 25% / 50% page-loss recovery
- Spectral camouflage: photo overlay in low-frequency spectrum
- Cross-platform: native GUI (Windows / Linux / macOS) + WASM (browser)
- Offline PWA: no network required
- Print-ready: fm_split + print.html for A4 sheets

## Quick start

Build native:

    cargo build --release
    ./target/release/fm_gui
    ./target/release/fm_selftest

Build WASM (browser):

    wasm-pack build --target web --out-dir web/pkg --no-default-features --features wasm
    cd web && python -m http.server 8080

## CLI

Encode single file:

    fm_encode photo.jpg photo.aero.png --password mypass
    fm_encode file.bin file.aero.png --border

Encode multi-page with resilience:

    fm_split book.pdf ./pages --resilience 3   # 25% recovery
    fm_split file.bin ./pages --resilience 4   # 50% recovery

Decode:

    fm_decode photo.aero.png restored.jpg --password mypass
    fm_decode pattern.png out.jpg --secret <64_hex_chars>

Batch process folders:

    fm_batch encode ./in ./out --password mypass --recursive --jobs 8
    fm_batch decode ./patterns ./restored --recursive

Generate keypair:

    fm_keygen write

## Resilience levels

| Level    | Data/Parity | Recovery | Overhead |
|----------|-------------|----------|----------|
| Off      | 200 / 0     | 0%       | +0%      |
| Low      | 190 / 10    | 5%       | +5%      |
| Balanced | 180 / 20    | 10%      | +11%     |
| High     | 150 / 50    | 25%      | +33%     |
| Extreme  | 100 / 100   | 50%      | +100%    |

## Security

- Argon2id (32 MiB, t=3, p=2) - identical on every platform
- XChaCha20-Poly1305 (24-byte nonce) - encrypt-then-MAC
- HMAC-SHA256 for header + payload integrity
- Ed25519 signatures (optional)
- zeroize scrubbing of key material
- forbid(unsafe_code)

See SECURITY.md for threat model.

## Project structure

    src/
      lib.rs           crate root
      error.rs         error types
      types.rs         AeroHeader, DataType, ResilienceLevel
      fec.rs           Reed-Solomon wrapper
      resilience.rs    parameterized page-level RS
      selftest.rs      round-trip verification
      fastmem.rs       size caps, atomic writes
      crypto/          AeroSeal v1/v2, Argon2id, Ed25519
      encoder/         AeroPack, AeroGlint FFT encoder, APNG
      decoder/         FFT decoder, QPSK, pilot detection
      app.rs           egui GUI
      icon.rs          application icon
      wasm.rs          WASM bindings
      bin/             CLI tools

    web/
      index.html       PWA scanner + encoder
      print.html       print pages to A4
      sw.js            service worker (offline cache)
      manifest.json    PWA manifest

    tests/
      property_tests.rs    proptest (10,000 cases)

    benches/
      aeropack_bench.rs    criterion benchmarks

## Technology

| Layer       | Implementation |
|-------------|----------------|
| Compression | AeroPack v20 (adaptive BWT+MTF+RLE+DPCM3, BCJ x86) |
| Transport   | 2D OFDM over FFT with QPSK, Hermitian symmetric |
| Pilots      | 4 tones at 30/60/120/150 deg, radius 0.50 Nyquist |
| Interleave  | SplitMix64 PRNG (fixed seed) |
| FEC         | RS(255, 223) + page-level RS resilience |
| Crypto      | XChaCha20-Poly1305, Argon2id, HMAC-SHA256, Ed25519, X25519 |
| Camouflage  | Photo in low-freq spectrum (r < 0.28) |

## License

MIT. See LICENSE.