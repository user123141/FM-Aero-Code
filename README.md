# FM Aero Code 2

**Optical data storage + invisible watermarking + cryptographic attestation.**

Try it: [user123141.github.io/FM-Aero-Code](https://user123141.github.io/FM-Aero-Code/)

## Three channels

| Mode | Purpose |
|---|---|
| AeroGlint | FFT 2D-OFDM pattern, printable, camera-readable |
| Stego | Invisible watermark (BitPerfect / Robust+Watson / DualB) |
| Attestation | Ed25519 + RFC 3161 TSA + OpenTimestamps + ZKP |

## Quick start

    cargo build --release --lib -j 1
    cargo build --release --bin fm_gui -j 1
    ./target/release/fm_gui

## CLI tools

| Binary | Purpose |
|---|---|
| fm_encode / fm_decode | AeroGlint pattern |
| fm_split | Multi-page APNG |
| fm_stego | Stego embed/extract |
| fm_status | Attestation + trust |
| fm_sign | Multi-sig, TSA, OTS, ZKP |
| fm_verify | Verify integrity |
| fm_selftest | Round-trip tests |
| fm_batch | Batch processing |
| fm_keygen | Key generation |

## Stego modes

| Mode | Survives | Capacity (512x512) | Notes |
|---|---|---|---|
| BitPerfect | PNG save/reload | ~98 KB | +-1 pixel |
| Robust+Watson | JPEG q>=60 | ~3 KB | adaptive delta |
| DualB | coexists with AeroGlint | ~32 KB | B-channel |

## Attestation + ZKP

- Ed25519 sign per-encode (per-install identity)
- RFC 3161 TSA (freetsa.org) HTTP request
- OpenTimestamps + Bitcoin block upgrade
- **ZKP: prove ownership without revealing private key**

## ZKP quick start

    fm_sign zkp-prove  file.png --seed <hex64>
    fm_sign zkp-verify file.png --pubkey H --r H --z H

## Docs

- [docs/USAGE.md](docs/USAGE.md)
- [docs/ATTESTATION.md](docs/ATTESTATION.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/RESEARCH.md](docs/RESEARCH.md)

## Security

AeroPack v20, AeroSeal v1/v2 (XChaCha20-Poly1305 + Argon2id),
Reed-Solomon RS(255,223), Ed25519, ZKP (Schnorr NIZK), #![forbid(unsafe_code)].

## License

MIT. See [LICENSE](LICENSE).