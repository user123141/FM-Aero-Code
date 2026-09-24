# FM Aero Code 2

**Optical data storage + invisible watermarking + cryptographic attestation.**

Try it: [user123141.github.io/FM-Aero-Code](https://user123141.github.io/FM-Aero-Code/)

## Three channels

| Mode | Purpose |
|---|---|
| AeroGlint | FFT-based printable pattern, camera-readable |
| Stego | Invisible watermark (BitPerfect / Robust / DualB) |
| Attestation | Ed25519 + RFC 3161 TSA + OpenTimestamps |

## Quick start

    cargo build --release --lib -j 1
    cargo build --release --bin fm_gui -j 1
    ./target/release/fm_gui

## CLI tools

- fm_encode / fm_decode - AeroGlint
- fm_split - Multi-page APNG
- fm_stego - Stego embed/extract
- fm_status - Attestation + trust
- fm_sign - Multi-sig + TSA + OTS
- fm_verify - Verify integrity
- fm_selftest - Round-trip tests
- fm_batch - Batch processing
- fm_keygen - Key generation

## Stego modes

| Mode | Survives | Capacity (512x512) |
|---|---|---|
| BitPerfect | PNG save/reload | ~98 KB |
| Robust | JPEG q>=60 | ~3 KB |
| DualB | Coexists with AeroGlint | ~32 KB |

## Security

AeroPack v20, AeroSeal v1/v2 (XChaCha20-Poly1305 + Argon2id),
Reed-Solomon RS(255,223), Ed25519 attestation, FMEX multi-sig,
#![forbid(unsafe_code)].

Full: [docs/ATTESTATION.md](docs/ATTESTATION.md)

## Docs

- [docs/USAGE.md](docs/USAGE.md)
- [docs/ATTESTATION.md](docs/ATTESTATION.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/RESEARCH.md](docs/RESEARCH.md)

## License

MIT. See [LICENSE](LICENSE).