# FM Aero Code 2

[![CI](https://github.com/user123141/FM-Aero-Code/actions/workflows/ci.yml/badge.svg)](https://github.com/user123141/FM-Aero-Code/actions/workflows/ci.yml)
[![Deploy](https://github.com/user123141/FM-Aero-Code/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/user123141/FM-Aero-Code/actions/workflows/deploy-pages.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

**Optical data storage in printable patterns + invisible photo watermarking.**

Encode any file into a printable spectral pattern that survives camera capture.
Or hide data inside a normal photo using DCT steganography - the photo looks unchanged.

Try it in your browser: **[user123141.github.io/FM-Aero-Code](https://user123141.github.io/FM-Aero-Code/)**

## Two independent channels

| Mode | What it does | Use case |
|---|---|---|
| **AeroGlint** (spectral) | Encodes bytes into 2D-OFDM over an FFT grid. Printable. Camera-readable. | QR-code alternative, printable backups, AR markers |
| **Stego** (DCT) | Embeds bytes into high-frequency DCT coefficients of a normal photo. Photo looks unchanged. | Watermarking, covert data in images, album/photo metadata |

Both can be combined: put an AeroGlint pattern on a page, then stego-hide metadata in the same image.

## AeroGlint pipeline

    file bytes
      -> AeroPack v20 (BWT + MTF + RLE + DPCM + BCJ x86, adaptive per block)
      -> AeroSeal v1/v2 (XChaCha20-Poly1305 + Argon2id, optional)
      -> Reed-Solomon RS(255, 223) FEC
      -> Optional page-level RS resilience (5 levels, 0-50%)
      -> PRNG bit interleaving (SplitMix64)
      -> QPSK onto 128x128 FFT grid (Hermitian symmetric)
      -> Photo in low-frequency cells (visual camouflage)
      -> 2D IFFT -> grayscale image
      -> PNG (single) or APNG (multi-page)

Decoder reverses: strip border -> FFT -> pilot-ring rotation -> QPSK demod
(multipass threshold) -> de-interleave -> RS decode -> decrypt -> unpack.

## Stego pipeline

    carrier photo (any RGB)
      + payload bytes
      -> optional AeroSeal v1 (XChaCha20-Poly1305)
      -> Reed-Solomon RS(255, 223) FEC
      -> header: FMS1 magic + FEC-len + flags + content-hash
      -> 8x8 block DCT on R channel
      -> QIM embed (Delta=14) into 54 high-freq coefficients per block
      -> 8-pass iterative refinement with integer rounding
      -> IDCT -> integer R -> stego photo (visually unchanged)

Extract: DCT each block -> read QIM parity -> header -> FEC -> decrypt -> verify hash.

## Features

**AeroGlint**
- Any file type: text, music, photos, video, executables, archives
- Bit-perfect round-trip: 9/9 self-tests + property-based tests
- Configurable resilience: 0% / 5% / 10% / 25% / 50% page-loss recovery
- Spectral camouflage: photo overlay in low-frequency spectrum (16x16 downsample)
- Soft decorations: stars (density slider), nebula clouds, ring/cross/checker frame
- Cross-platform: native GUI (Windows / Linux / macOS) + WASM (browser)
- Print-ready: fm_split + print.html for A4 sheets

**Stego**
- Carrier photo looks visually unchanged
- Bit-perfect extraction after PNG save/reload
- Optional password encryption (AeroSeal v1)
- Capacity: ~27 KB @ 512x512, ~108 KB @ 1024x1024
- CLI + GUI + WASM

## Quick start

    cargo build --release --lib -j 1
    cargo build --release --bin fm_gui -j 1
    ./target/release/fm_gui

Run self-tests:

    ./target/release/fm_selftest

## CLI

**AeroGlint encode/decode:**

    fm_encode photo.jpg photo.aero.png --password mypass
    fm_encode file.bin file.aero.png --border
    fm_decode photo.aero.png restored.jpg --password mypass

**Multi-page with resilience:**

    fm_split book.pdf ./pages --resilience 3   # 25% recovery
    fm_split file.bin ./pages --resilience 4   # 50% recovery

**Steganography:**

    fm_stego capacity cover.png
    fm_stego embed cover.png secret.bin stego.png --password hunter2
    fm_stego extract stego.png recovered.bin --password hunter2

**Batch:**

    fm_batch encode ./in ./out --password mypass --recursive --jobs 8
    fm_batch decode ./patterns ./restored --recursive

**Keypair:**

    fm_keygen write

## Resilience levels

| Level | Data/Parity | Recovery | Overhead |
|-------|-------------|----------|----------|
| Off | 200 / 0 | 0% | +0% |
| Low | 190 / 10 | 5% | +5% |
| Balanced | 180 / 20 | 10% | +11% |
| High | 150 / 50 | 25% | +33% |
| Extreme | 100 / 100 | 50% | +100% |

## Stego capacity

| Carrier | Payload capacity |
|---|---|
| 256x256 | ~24 KB |
| 342x584 | ~64 KB |
| 512x512 | ~98 KB |
| 1024x1024 | ~390 KB |
| 2048x2048 | ~1.5 MB |

## Security

- Argon2id (32 MiB, t=3, p=2) - identical on every platform
- XChaCha20-Poly1305 (24-byte nonce) - encrypt-then-MAC
- HMAC-SHA256 for header + payload integrity
- Ed25519 signatures (optional)
- zeroize scrubbing of key material
- `#![forbid(unsafe_code)]`

See [SECURITY.md](SECURITY.md) for threat model.

## Project structure

    src/
      lib.rs              crate root
      error.rs            error types
      types.rs            AeroHeader, DataType, ResilienceLevel
      fec.rs              Reed-Solomon wrapper
      resilience.rs       page-level RS for AeroFlow
      selftest.rs         round-trip verification
      fastmem.rs          size caps, atomic writes
      settings.rs         persistent GUI settings
      crypto/             AeroSeal v1/v2, Argon2id, Ed25519, X25519
      encoder/            AeroPack, AeroGlint FFT, APNG, print
      decoder/            FFT decoder, QPSK, pilot detection
      steganography/      DCT + QIM watermarking
      app.rs              egui GUI (4 tabs: Pattern/Decoded/Keys/Stego)
      icon.rs             application icon
      wasm.rs             WASM bindings
      bin/                CLI tools

    web/                  PWA + print
    tests/                golden + property tests
    benches/              criterion benchmarks

## Technology

| Layer | Implementation |
|---|---|
| Compression | AeroPack v20 (adaptive BWT+MTF+RLE+DPCM, BCJ x86) |
| Transport | 2D OFDM over FFT, QPSK, Hermitian symmetric |
| Pilots | 4 tones at 30/60/120/150 deg, radius 0.50 Nyquist |
| Interleave | SplitMix64 PRNG (fixed seed) |
| FEC | RS(255, 223) + page-level RS resilience |
| Crypto | XChaCha20-Poly1305, Argon2id, HMAC-SHA256, Ed25519, X25519 |
| Camouflage | Photo in low-freq spectrum (r < 0.18) |
| Stego | 8x8 DCT + QIM (Delta=14) on R channel |

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for detailed plan.

**Next up (v3.7.x / v3.8.x):**
- Robust stego mode (survives JPEG q=60, spread-spectrum)
- Stego strength slider in GUI
- Web stego UI (drag photo + payload in browser)
- Finder patterns for camera scan (QR-like corner markers)
- Adaptive binarization (Sauvola) for uneven lighting
- Soft-decision RS decoding (LPR erasures)

**Later (v4.x):**
- Progressive decoding (metadata in low-freq, payload in high-freq)
- 16-QAM / 64-QAM adaptive constellations
- Dot-gain pre-emphasis for printer compensation
- Inter-frame APNG compression (video mode)
- WebGL/WebGPU FFT
- WebWorkers + WASM threads
- Zero-copy WASM pipeline

## License

MIT. See [LICENSE](LICENSE).
## Why FM Aero Code beats GPG / detached signatures

Traditional signatures (GPG, PKI) live in a **separate file** (`.sig`, `.asc`). They are:

- **Detachable** - a sender or CDN can strip the signature; the file still opens
- **Visible** - everyone sees "this file has a signature"; your watermarking is not covert
- **Fragile** - any re-encoding (JPEG, screenshot, print) destroys the signature
- **Opaque** - end user needs a GPG-compatible client, key management, trust chains

FM Aero Code's stego channel embeds the signature **inside the pixels**:

| Property | GPG | FM Aero Code (FMS3) |
|---|---|---|
| Signature is visible in file | yes (`.sig`/`.asc`) | **no** (hidden in DCT/LSB) |
| Detachable without damage | yes | **no** (part of the image) |
| Survives JPEG q>=85 | no | **yes** (Robust mode) |
| Survives screenshots | no | yes (Robust mode) |
| Self-contained (no external file) | no | **yes** |
| Author + license + timestamp bound | partially | **yes (single Ed25519 sig)** |
| Verifier needs special tool | gpg | any browser (WASM) |
| Covert watermarking | no | **yes** |
| AI-inpainting detector | no | **yes** (hash binding) |
| Print-friendly | no | **yes** (AeroGlint side) |

**Use cases GPG cannot solve:**
- Prove authenticity of a photo posted on social media (JPEG-recompressed)
- Protect art from AI-inpainting (any re-paint invalidates hash + signature)
- Ship legal documents with author + license + timestamp embedded invisibly
- Print a certificate with hidden authenticity check
- Watermark photos before sharing (BitPerfect for PNG, Robust for Instagram)

**Attack that GPG cannot stop but FMS3 can detect:**
- AI re-generates the photo -> Robust layer corrupted -> signature invalid
- Editor removes author metadata -> signature invalid (author is in signed JSON)
- Attacker replaces file with lookalike -> hash mismatch
- Malicious timestamp -> signature invalid

**Long-term roadmap:**
- v4.x: **Dual-layer** (BitPerfect detects tampering + Robust survives re-encode)
- v4.x: **Chain of custody** - each re-sign adds a block
- v5.x: **Blockchain anchor** - timestamp cross-verified on public chain
- v5.x: **Multi-signature** - author + timestamp authority + validator
## Detailed roadmap (v3.9.x - v5.x)

### v3.9.x - Stego polishing

- **v3.9.6** *(current)* - capacity fix, 12-coeff Robust, decoded card metadata
- **v3.9.7** - web stego UI (index.html toggle AeroGlint/Stego), scanner auto-retry
- **v3.9.8** - Dual-layer embed (Robust + BitPerfect in one image)
- **v3.9.9** - ARQ feedback: show missing pages, request re-transmit

### v3.10.x - AeroGlint expansion

- **v3.10.0** - RGB-dup: 3x density in same 128x128 grid (3 independent FFTs)
- **v3.10.1** - Watson perceptual masking for adaptive QIM delta
- **v3.10.2** - Cross-channel calibration for camera color shifts
- **v3.10.3** - Dot-gain pre-emphasis for print quality
- **v3.10.4** - Soft-decision RS decoding (erasure-aware)

### v4.x - Performance + robustness

- **v4.0.0** - WebGL/WebGPU FFT (60 FPS browser scanner)
- **v4.0.1** - WebWorkers + WASM threads (wasm-bindgen-rayon)
- **v4.0.2** - Zero-copy WASM frame pipeline
- **v4.1.0** - Fountain codes (LT/Raptor) - 50% loss recovery
- **v4.2.0** - Progressive decoding (metadata in low freqs, payload in high)
- **v4.3.0** - Timestamp authority + blockchain anchor
- **v4.4.0** - Multi-signature (author + validator + TSA)

### v5.x - AI + advanced

- **v5.0.0** - AI-robust stego (learn to survive inpainting)
- **v5.0.1** - Stego stability vs Topaz Gigapixel upscaling
- **v5.1.0** - Zero-knowledge proof of ownership
- **v5.2.0** - Adaptive constellation (QPSK/16-QAM/64-QAM auto)
- **v5.3.0** - Video mode (AeroPack Video, inter-frame compression)

### Not planned

- QR-code fallback (redundant - we have a better native format)
- Detached GPG-style `.sig` files (defeats the point of covert stego)