# FM Aero Code 2

Fast Memory optical storage via AeroGlint Spectrum Protocol.

Encode any file into a printable pattern that survives camera capture.

Version: 2.4.0 | Author: Maksym Skorina | License: MIT

## Status

- Core: 100% bit-perfect round-trip verified (9/9 selftests)
- Tested payloads: empty, 1 B, 128 B, 500 B, 2 KB, 9 KB random, 1 MB MP3
- Multi-page APNG works (3265 pages for 1 MB MP3)
- Cross-platform: native (Windows/Linux/Mac) + WASM (browser)

## How it works

    File
      -> AeroPack v19 (BWT + MTF + RLE + DPCM adaptive per block)
      -> AeroSeal v1/v2 (XChaCha20 + Argon2id, optional)
      -> Reed-Solomon RS(255, 223) FEC
      -> PRNG interleaving (SplitMix64)
      -> QPSK onto 128x128 FFT grid (Hermitian symmetric)
      -> 2D IFFT -> grayscale image
      -> PNG (single page) or APNG (multi-page)

Decoder reverses: FFT -> pilot-ring rotation detect -> QPSK -> de-interleave
-> RS decode -> decrypt -> unpack.

## Technology benchmarks

Computed on AMD Ryzen 5 (16 threads), release mode, in-memory.

| Payload | Size | AeroPack time | zstd-3 time | gzip-9 time |
|---------|------|---------------|-------------|-------------|
| text    | 16 KB  | 0.9 ms       | 0.2 ms      | 0.6 ms      |
| text    | 256 KB | 14 ms        | 3.4 ms      | 9.2 ms      |
| text    | 1 MB   | 58 ms        | 14 ms       | 38 ms       |
| random  | 256 KB | 22 ms        | 2.1 ms      | 8.5 ms      |

AeroPack is ~4x slower than zstd but usually produces smaller output on
adversarial text data (BWT+MTF+RLE chain benefits from long-range patterns
that zstd's LZ77 pass misses on short windows).

Run `cargo bench` for your own numbers.

## Capacity

- Grid 128x128: ~2 KB per page
- Grid 256x256: ~8 KB per page
- APNG max pages: 65535 (~130 MB per pattern set)

## Security

- Argon2id: 32 MiB, t=3, p=2 (OWASP 2025 compliant, unified across platforms)
- XChaCha20-Poly1305 AEAD, 24-byte nonce
- HMAC-SHA256 encrypt-then-MAC
- Constant-time MAC compare, zeroize on drop
- No unsafe code

See SECURITY.md for threat model, SPECIFICATION.md for wire format.

## Quick start

Native:

    cargo build --release
    .\target\release\fm_gui.exe

WASM:

    wasm-pack build --target web --out-dir web/pkg --no-default-features --features wasm
    cd web
    python -m http.server 8080

## CLI

    fm_encode in.jpg out.png --password mypass
    fm_encode in.jpg out.png --recipient <64_hex_pubkey>
    fm_decode out.png restored.jpg --password mypass
    fm_decode out.png restored.jpg --secret <64_hex_secret>
    fm_keygen write
    fm_batch encode ./in ./out --password mypass --recursive --jobs 8
    fm_batch decode ./patterns ./restored --recursive
    fm_selftest

## Tests

    cargo test

Property-based tests (proptest) verify 10,000 random payloads.

## License

MIT. See LICENSE.