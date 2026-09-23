# FM Aero Code 2 - Usage Guide

## Two modes

GUI has toggle in left panel: AeroGlint / Stego.

### AeroGlint - printable patterns

Encode:
1. Source: file or text
2. Optional: Encryption, Compression, Center logo, decorations
3. ENCODE (Ctrl+E)
4. Save PNG (Ctrl+S)

Decode:
1. Source: pattern PNG
2. DECODE file (Ctrl+D) or DECODE from RAM
3. Decoded tab shows name, type, size, hash, OFFICIAL badge

Print: side panel -> format (PNG/HTML/SVG/PDF) -> Save print.

### Stego - hide in photos

Embed:
1. Left panel: Stego mode
2. Choose: Bit-perfect (PNG-safe) or Robust (JPEG-safe)
3. Load photo (carrier)
4. Load payload or type text
5. Optional: Author, License, signing seed
6. Test round-trip first (verifies in RAM)
7. EMBED into photo
8. Save output

Extract:
1. Load stego image or use last output
2. EXTRACT payload
3. Card shows name, type, size, sha, author, license, signature

## Stego modes

| Mode | Survives | Visual |
|---|---|---|
| Bit-perfect | PNG save/reload | +-1 pixel, invisible |
| Robust | JPEG q>=60 | invisible in practice |
| DualB | coexists with AeroGlint | B-channel only |

Bit-perfect for archival. Robust for social media.

## Attestation

First run: fm_identity.json (per-install Ed25519).
Binary built with fm_root.key: root pubkey embedded + matched against
signed fm_trust.json -> your encodes are OFFICIAL BUILD.

- Author: keep fm_root.key secret
- User: nothing to do
- Pirate fork: no BUILD_TOKEN -> Unsigned

### Share root

Click ? -> About -> Export QR PNG. Scan with phone -> fm_trust.local.json.

### CLI

    fm_status                       Full status
    fm_status --export-root
    fm_status --export-root-qr o.png
    fm_status --import-root <hex>
    fm_status --fingerprint <hex>

## Multi-signature

    fm_sign list   myfile.png
    fm_sign add    myfile.png --purpose author    --seed <hex64>
    fm_sign add    myfile.png --purpose validator --seed <hex64>
    fm_sign tsa    myfile.png --url http://freetsa.org/tsr
    fm_sign ots    myfile.png
    fm_sign verify myfile.png

Signatures live in FMEX block inside the PNG.

## CLI cheatsheet

    # AeroGlint
    fm_encode  <input> <output.png> [--password X] [--border]
    fm_decode  <pattern.png> <output> [--password X]

    # Stego
    fm_stego embed   <carrier> <payload> <out.png> [--password X] [--robust]
    fm_stego extract <stego.png> <out> [--password X]

    # Multi-page
    fm_split <input> <out_dir> [--resilience 0-4]

    # Batch
    fm_batch encode|decode <in> <out> [--recursive]

    # Identity / trust
    fm_status [--trust|--identity|--export-root|--export-root-qr <png>|--import-root <hex>]

    # Multi-sig
    fm_sign list|add|verify|tsa|ots <file.png>

## Toggles

| Control | Effect |
|---|---|
| Encryption | AeroSeal v1 password protection |
| Compression | Auto / Lossless / Lossless Priority |
| Resilience | Page-level RS recovery (0-50%) |
| Detection border | Black frame for camera |
| Stars | Decorative white dots (3-tier) |
| Nebula | Soft cloudy background |
| Frame | Ring / Cross / Checker |
| Center logo | Photo in low-freq center |

## FAQ

Q: "Unsigned" decoded?
A: Built without fm_root.key OR fork. Check fm_status.

Q: Stego "no FMS3 magic"?
A: You loaded the original carrier, not the stego output.

Q: Where are fm_identity.json / fm_trust.json?
A: Next to fm_gui.exe.