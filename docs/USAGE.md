# FM Aero Code 2 - Usage Guide

## Two modes

GUI: toggle in left panel: AeroGlint / Stego.

### AeroGlint - printable patterns

Encode:
1. Source: file or text
2. Optional: Encryption, Compression, Center logo, decorations
3. ENCODE (Ctrl+E)
4. Save PNG (Ctrl+S)

Decode:
1. Source: pattern PNG (or photographed)
2. DECODE file (Ctrl+D) or DECODE from RAM
3. Decoded tab shows name, type, size, hash, OFFICIAL badge

### Stego - hide in photos

Embed:
1. Left panel -> Stego mode
2. Choose: Bit-perfect / Robust+Watson
3. Load photo (carrier)
4. Load payload or type text
5. Optional: Author, License, signing seed
6. Test round-trip (in RAM)
7. EMBED into photo
8. Save output

Extract:
1. Load stego image or use last output
2. EXTRACT payload
3. Card shows name/type/size/sha/author/license/signature

## Stego modes

| Mode | Survives | Visual |
|---|---|---|
| Bit-perfect | PNG save/reload | +-1 pixel |
| Robust+Watson | JPEG q>=60 | adaptive delta per block |
| DualB | coexists with AeroGlint | B-channel only |

## Attestation

First run: fm_identity.json (per-install Ed25519).
Binary built with fm_root.key: root pubkey embedded.
All encodes are OFFICIAL BUILD.

### ZKP (prove ownership)

    fm_sign zkp-prove  file.png --seed <hex64>
    -> outputs: pubkey, r, z, file_hash
    fm_sign zkp-verify file.png --pubkey H --r H --z H
    -> "ZKP: VALID"

Share (pubkey, r, z, file_hash) with any verifier.
Verifier confirms you own the key WITHOUT learning the seed.

### Bitcoin timestamp (OTS)

    fm_sign ots <file>              # create .ots proof
    fm_sign ots-upgrade <file>.ots  # fetch Bitcoin block height

Once Bitcoin-anchored: proof verifiable forever.

## Multi-signature

    fm_sign list   <file.png>
    fm_sign add    <file.png> --purpose author    --seed H
    fm_sign add    <file.png> --purpose validator --seed H
    fm_sign tsa    <file.png> --url http://freetsa.org/tsr
    fm_sign verify <file.png>

## CLI cheatsheet

    fm_encode  <input> <output.png> [--password X] [--border]
    fm_decode  <pattern.png> <output> [--password X]
    fm_stego embed   <carrier> <payload> <out.png> [--password X] [--robust]
    fm_stego extract <stego.png> <out> [--password X]
    fm_split <input> <out_dir> [--resilience 0-4]
    fm_batch encode|decode <in> <out> [--recursive]
    fm_status [--trust|--identity|--export-root|--export-root-qr <png>|--import-root <hex>]
    fm_sign list|add|verify|tsa|ots|ots-upgrade|zkp-prove|zkp-verify <file>

## FAQ

Q: "Unsigned" decoded?
A: Built without fm_root.key OR made by fork. Check fm_status.

Q: Stego "no FMS3 magic"?
A: Loaded the original carrier, not the stego output.

Q: ZKP INVALID?
A: pubkey does not match seed OR file changed after proof.

Q: Where are fm_identity.json / fm_trust.json?
A: Next to fm_gui.exe.