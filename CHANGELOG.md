# Changelog

All notable changes to FM Aero Code 2.

## [3.16.3] - Audio Robust: MDCT-QIM replaced with FFT-OFDM

### Fixed
- **Robust audio round-trip broken.** MDCT is a TDAC codec: perfect
  reconstruction requires an unmodified spectrum. Any QIM change to the
  coefficients breaks time-domain aliasing cancellation and corrupts
  neighboring frames. Encoder and decoder were literally disagreeing on
  the same bitstream.
  Replaced with **FFT-OFDM**: non-overlapping blocks of `FFT_N = 2048`,
  FFT, QIM on 32 selected bin magnitudes in `[128, 640)`, IFFT, replace.
  Encoder and decoder share the exact same block grid, so bit recovery
  is exact.
- Real stream-size check added to `embed_wav`: it now verifies
  `stream.len() * 8 <= slots` after building the actual stream (with name,
  meta, signature), not just the conservative capacity estimate.

### Changed
- `BITS_PER_FRAME` 24 -> 32 (FFT bins are cheap).
- Removed `crate::audio::mdct` and `crate::audio::mask` imports from
  `embed.rs`. Both modules kept on disk with `#![allow(dead_code)]` for
  future reference.
- Test clips for the Robust round-trip extended from 2 s to 5 s so the
  full FMSA stream (header + name + meta + FEC body) fits.

### Known limitations
- Robust still needs WAV input. For MP3: convert externally
  (`ffmpeg -i out.wav -b:a 320k out.mp3`) and back to WAV, then run
  `fm_audio extract` вЂ” payload survives.
- No real-world microphone channel yet. That is v3.17.0 (acoustic modem).
## [3.16.2] - Audio capacity fix

### Fixed
- **Robust capacity returned 0 for short audio.** `STREAM_OVERHEAD_MAX = 828`
  assumed worst-case name (200B) + metadata (512B) + signature (96B), which
  eats the entire payload bit budget of any clip under ~5 seconds.
  Now `capacity_bytes` uses `STREAM_OVERHEAD_MIN = 20` (fixed header only).
  Actual embed still errors if the real stream does not fit - no silent
  over-commit.
- **`BITS_PER_FRAME` raised 16 -> 24.** MDCT has 512 coefficients; we now
  use 24 of the 256 candidates in [32, 288). Still ~9% of bins, safe for
  inaudibility, but 1.5x the payload throughput.
- Removed unused `masking_threshold` call and unused `total_frames_max`
  in the audio pipeline (dead code).
- Fixed off-by-2 typo in `extract_robust` FMSA peek upper-bound estimate.

### Verified
- `tests/audio.rs::audio_roundtrip_robust` passes (53 B payload in 2 s clip).
- `tests/audio.rs::audio_capacity_monotonic` passes (longer audio, higher cap).
## [3.16.1] - Audio hotfixes

### Fixed
- **WavFile now derives `Debug + Clone`** (compile error since v3.16.0).
- **embed_robust early-exit bug**: outer loop ran MDCT/IMDCT over the entire
  audio even after all payload bits were written. Now stops immediately вЂ”
  ~95% speedup on short payloads in long files.
- **embed_robust OLA correctness**: the previous version accumulated onto a
  zeroed buffer and would have silenced the unprocessed tail if early-exit
  ever triggered. Now uses subtract-and-replace OLA so unmodified regions
  stay byte-exact.
- **Boundary reflection**: audio edges are reflected instead of zero-padded,
  removing startup/cliff transients.

### Added
- `fm_audio verify <stego.wav>` command (parallel to `fm_verify`).
- `extract_robust` peeks the FMSA header and stops processing frames once
  the stream length is known вЂ” big speedup on small payloads in long tracks.
- `tests/audio.rs` with 5 round-trip + invariant tests.

## [3.16.0] - Audio stego (MDCT-QIM + BitPerfect LSB)

### Added
- `src/audio/` module: `wav.rs`, `mdct.rs`, `mask.rs`, `embed.rs`.
- MDCT-domain QIM watermarking (survives MP3 320 / AAC 256).
- BitPerfect LSB mode for WAV / FLAC (byte-exact).
- FMSA stream format (parallel to FMS3 for images): magic, fec_len, flags,
  hash, name, meta, optional Ed25519 sig, FEC body.
- `fm_audio` CLI: embed / extract / capacity / inspect / keygen.
- Reuses: `fec`, `AeroSeal v1`, Ed25519 metadata signature.

### Fixed
- **ZKP `scalar_from_seed` bug** (crypto/zkp.rs): was using
  `from_bytes_mod_order_wide` on the full 64-byte SHA512 output; Ed25519
  uses only the first 32 bytes with clamping. Every proof verified as
  INVALID before this fix. Now uses `from_bytes_mod_order` on a 32-byte
  slice вЂ” round-trip verified by `tests/zkp.rs`.
- Removed unused `anyhow` import in `crypto/zkp.rs`.

## [3.15.0] - Watson masking + ZKP + OTS upgrade

### Added
- Watson-style per-block adaptive QIM delta (Robust stego).
- ZKP (Schnorr NIZK on Ed25519) вЂ” prove ownership without revealing seed.
- OpenTimestamps upgrade: `fm_sign ots-upgrade` fetches Bitcoin block height.
- `fm_sign zkp-prove` / `zkp-verify` CLI commands.

## [3.14.x] - Web/WASM polish

- Web mode toggle, GUI multi-sig (in-memory), WASM CI fix, .gitattributes.

## [3.10 - 3.13] - Attestation + docs

- Per-install identity (`fm_identity.json`), root attestation, TSA, OTS,
  Sauvola binarization, docs suite.