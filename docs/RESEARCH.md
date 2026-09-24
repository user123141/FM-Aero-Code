# Deep Features - Research & Implementation Plan

Each feature below needs a dedicated development session. This file
is the reference spec so no detail gets lost.

## 1. Progressive Decoding

**Goal:** decoder shows metadata + partial payload even with poor focus/blur.

**Idea:** low frequencies survive blur; split data across spectrum bands.
- Low freq band (r < 0.18): header + first 512 bytes + file preview
- Mid band (0.20 < r < 0.50): main payload
- High band (r > 0.50): remainder

**Changes:**
- encoder/aeroglint.rs: split stream into 3 FEC blocks, place in 3 bands
- decoder/aeroglint.rs: decode bands independently, return Partial { metadata, bytes_so_far }
- GUI: show "Decoding 15%..." + partial preview

**Effort:** 2 sessions. Files touched: aeroglint.rs (enc+dec), pipeline.rs (dec).

## 2. Fountain Codes (LT / Raptor)

**Goal:** survive 50% page loss without doubling parity.

**Idea:** infinite stream of encoded "drops"; any N of them reconstruct file.
- Replace page-level RS(255,223) with LT-code over pages
- RNG seed in header; decoder computes expected drop indices
- Luby transform: degree distribution, XOR combinations

**Changes:**
- src/resilience.rs: add LT encode/decode (100 lines)
- encoder/pipeline.rs: replace add_parity_n with lt_encode
- decoder/pipeline.rs: replace recover_group_n with lt_decode
- Header: flag HEADER_FLAG_FOUNTAIN

**Effort:** 3 sessions. Risk: solver loops, degree distribution tuning.

## 3. WebGL / WebGPU FFT

**Goal:** 60 FPS browser scanner (currently ~5 FPS).

**Idea:** 128x128 complex FFT on GPU via WebGL2 transform feedback or WebGPU compute shader.

**Changes:**
- new web/fft.wgsl (or fft.glsl) shader
- wasm.rs: expose upload_frame(bytes) + read_spectrum()
- pipeline.js: orchestrate GPU passes

**Effort:** 4 sessions. Fallback: keep WASM FFT for old browsers.

## 4. Watson Perceptual Masking

**Goal:** adaptive QIM delta per block; invisible on smooth, robust on texture.

**Idea:** compute local activity from DCT coefficients (std of neighbors);
set delta = max(delta_min, mask * activity) where mask ~ 0.1..0.5.

**Changes:**
- steganography/embed.rs: compute per-block delta before qim_place
- QIM_DELTA_SET stays as min bound

**Effort:** 1 session.

## 5. RGB-Density (3x)

**Goal:** 3x capacity in same 128x128 grid.

**Idea:** three independent FFT grids, one per channel R/G/B.
Camera demosaic preserves channel separation well enough for FFT.

**Changes:**
- encoder/aeroglint.rs: encode_stream_rgb(stream_r, stream_g, stream_b)
- decoder/aeroglint.rs: decode per channel, concatenate bits
- Header flag HEADER_FLAG_RGB

**Effort:** 2 sessions. Risk: color drift, gamma.

## 6. 16-QAM / 64-QAM adaptive

**Goal:** 2-3x density when scanning from clean PNG / perfect screen.

**Idea:** header flag constellation; QPSK / 16-QAM / 64-QAM.
- 16-QAM: 4 bits/cell -> 2x
- 64-QAM: 6 bits/cell -> 3x
- Detector probes pilot amplitude -> picks constellation on decode

**Changes:**
- encoder/aeroglint.rs: qam_modulate(bits, order)
- decoder/aeroglint.rs: adaptive threshold -> demod
- Header: byte for constellation

**Effort:** 2 sessions.

## 7. Blockchain Anchor (Bitcoin OTS)

**Goal:** public timestamp proof cross-verifiable.

**Idea:** OpenTimestamps already integrated in fm_sign ots. Extend:
- After `ots stamp`, embed the .ots file hash + Merkle path in FMEX
- Optionally poll opentimestamps.org for upgrade to Bitcoin block

**Changes:**
- tsa.rs: add ots_verify(ots_bytes) -> Option<block_height>
- multisig.rs: new field anchor_block_height

**Effort:** 1 session (mostly CLI + parsing).

## 8. Zero-Knowledge Proof of Ownership

**Goal:** prove you know the private key that signed a file WITHOUT revealing it.

**Idea:** Schnorr NIZK on Ed25519:
- Prover knows seed s, pubkey P = sG
- Commitment r = kG, challenge c = H(P || r || file_hash), response z = k + c*s
- Verifier checks zG == r + cP

**Changes:**
- crypto/zkp.rs (new module ~80 lines)
- fm_sign zkp-prove / zkp-verify CLI

**Effort:** 1 session. Uses ed25519-dalek scalar math.

## General rules

- Never break existing format backwards compat
- Each feature: flag in AeroHeader; old decoders ignore flags
- Tests: extend tests/golden.rs and tests/property_tests.rs
- CI: check native + wasm on every commit