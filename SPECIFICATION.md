# FM Aero Code 2 - Format Specification

Version 2.4.0

## 1. Overview

FM Aero Code 2 encodes arbitrary binary data into a printable black-and-white
pattern that survives real-world camera capture. Unlike QR codes, it uses
2D OFDM modulation over FFT, giving robustness to rotation, scale, and
mild perspective distortion.

Pipeline:

    file bytes
      -> AeroPack (BWT + MTF + RLE + DPCM adaptive)
      -> AeroSeal (XChaCha20-Poly1305 + Argon2id + HMAC, optional)
      -> AeroGlint FEC (Reed-Solomon RS(255,223))
      -> PRNG bit interleaving
      -> QPSK onto 128x128 FFT grid (Hermitian symmetric)
      -> 2D IFFT -> grayscale image
      -> APNG (single or multi-page)

## 2. Wire format

### 2.1 AeroHeader (128 bytes)

Offset | Size | Field
-------|------|------
0      | 3    | Magic = "FM2"
3      | 1    | Version = 2
4      | 1    | DataType (0=Text, 1=Audio, 2=Image, 3=Document, 4=Raw, 5=Exe, 6=Archive, 7=Video)
5      | 1    | CompressionKind (0 = AeroPack v19)
6      | 1    | CipherKind (0=None, 1=SealV1, 2=SealV2)
7      | 1    | Flags
8..11  | 4    | original_size (u32 LE)
12..15 | 4    | payload_size (u32 LE)
16..17 | 2    | checksum (fnv16 of first 22 bytes)
18..19 | 2    | page_index (u16 LE)
20..21 | 2    | page_total (u16 LE)
22..29 | 8    | content_hash (SHA-256 prefix)
30..93 | 64   | Ed25519 signature (optional)
94..109| 16   | HMAC-SHA256 prefix (optional)
110..113| 4   | reserved (unix timestamp, u32 LE)
114..127| 14  | padding (zeros)

### 2.2 AeroSeal v1 blob

    [salt: 16B][nonce: 24B][ciphertext + Poly1305 tag][HMAC-SHA256: 32B]

- Argon2id(password, salt, 32MiB, t=3, p=2) -> master key
- HKDF(master, "enc", 32B) -> encryption key
- HKDF(master, "mac", 32B) -> MAC key
- XChaCha20-Poly1305(enc_key, nonce, AAD=magic||mode||salt||nonce)
- HMAC-SHA256(mac_key, salt||nonce||ciphertext)

### 2.3 AeroSeal v2 blob (single recipient)

    [eph_pub: 32B][salt: 16B][nonce: 24B][ciphertext + tag][HMAC: 32B]

- X25519(ephemeral_secret, recipient_public) -> shared
- HKDF(shared, salt, "enc2"|"mac2", 32B each)

### 2.4 AeroSeal v2 multi-recipient

    [count: u16][ (rid: 8B, len: u32, block)*count ]

Each block is a v2 single-recipient envelope. rid = SHA-256(public)[:8].

## 3. AeroPack v19

Frame:

    [magic: 2B = 0x7B 0xA3][version: 1B][class: 1B]
    [block_size: u32][block_count: u32]
    ( [method: 1B][orig_len: u32][comp_len: u32][payload] ) * block_count

Methods (byte after xor with 0x5A):

Value | Method
------|-------
0     | Raw (zstd pass-through)
1     | DPCM order 1 + zstd
2     | DPCM order 2 + zstd
3     | RLE + zstd
4     | BWT -> MTF -> RLE -> zstd
5     | RawStored (no compression)

Block size depends on data class:
- Audio: 32 KB
- Document: 16 KB
- Text: 8 KB
- Generic: 4 KB

Each block independently chooses its best method by min encoded size.

## 4. AeroGlint spectral layer

### 4.1 Cell layout (128x128)

- DC cell (0, 0): unused (mean removed).
- Guard band (radial): 0.14 <= |f| <= 0.85 normalized to Nyquist.
- Pilots at angles 30, 60, 120, 150 degrees, radius 0.50. Values:
  (4+0j), (3+0j), (2+0j), (1+0j). Their Hermitian mirrors form 8 unique cells.
- Data cells: upper half-plane canonical representatives only.
  For each pair {(x,y), (N-x, N-y)}, keep the lexicographically smaller one.

### 4.2 QPSK mapping

Each data cell carries 2 bits (b1, b2):
    symbol = (-1)^(1-b1) + i*(-1)^(1-b2)
        00 -> (-1) + (-1)i
        01 -> (-1) + (+1)i
        10 -> (+1) + (-1)i
        11 -> (+1) + (+1)i

Before QPSK, bits are PRNG-shuffled (SplitMix64 seed 0x464D2D4145524F32).
Decoder uses the same permutation. This spreads burst errors across RS blocks.

### 4.3 Hermitian symmetry

For every cell (x, y) with symbol S:
    matrix[N-y][N-x] = conj(S)

This ensures the IFFT output is real-valued (required for pixel storage).

### 4.4 Decoder pipeline

1. Resize input to 128x128 (Triangle interpolation).
2. Subtract mean (removes DC offset).
3. 2D FFT.
4. Find 4 strongest peaks near pilot ring. Match against expected pilot
   angles (with their 180-degree mirrors) to derive rotation delta.
5. Rotate spectrum back.
6. Threshold: cells with amplitude < 0.5 * median are treated as (0, 0).
7. QPSK demodulate.
8. De-interleave (same SplitMix64 seed).
9. Reed-Solomon decode per 255-byte block (corrects up to 16 errors).

## 5. Security

- Argon2id: 32 MiB / t=3 / p=2 on all platforms (native, WASM, mobile).
- AEAD: XChaCha20-Poly1305, 24-byte nonce, AAD bound.
- HMAC-SHA256 over (salt || nonce || ciphertext): encrypt-then-MAC.
- Constant-time comparison for all MAC verifications.
- zeroize crate scrubs key material on drop.
- No unsafe code in this crate (#![forbid(unsafe_code)]).

## 6. Limits

- MAX_COMPRESSED_BYTES = 256 MiB
- MAX_DECOMPRESSED_BYTES = 512 MiB
- Single-page capacity: ~2 KB
- Multi-page (AeroFlow) capacity: 65535 pages ~= 130 MB per pattern set

## 7. Known limitations

- Rotation detection is approximate (pilot peak angle to nearest cell).
  Sub-pixel interpolation is implemented but not currently used.
- No DQPSK: phase tracking between APNG frames is not implemented.
  Multi-page streaming assumes each frame independently decodable.
- No gamma correction: real camera tests may need a pre-emphasis filter.