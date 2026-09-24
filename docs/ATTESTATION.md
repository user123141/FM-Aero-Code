# Attestation - how FM Aero Code proves authorship

## Four layers

| Layer | What it does |
|---|---|
| Ed25519 sign | per-encode, per-install identity |
| RFC 3161 TSA | trusted timestamp from freetsa.org |
| OpenTimestamps | Bitcoin block anchor (public) |
| ZKP (Schnorr NIZK) | prove key ownership without revealing key |

## Scheme

### Files

| File | Owner | Purpose |
|---|---|---|
| fm_root.key | author (gitignored) | 32-byte Ed25519 seed |
| ROOT_PUBKEY | embedded at build | 32-byte pubkey |
| BUILD_TOKEN | embedded at build | 64-byte signature |
| fm_trust.json | author (public) | Trusted roots (signed) |
| fm_trust.json.sig | author (public) | Ed25519 sig of fm_trust.json |
| fm_trust.local.json | user | User roots (unverified) |
| fm_identity.json | per-install | Local Ed25519 seed |

### Author flow

1. fm_root.key in repo
2. cargo build -> build.rs signs commitment
3. ROOT_PUBKEY + BUILD_TOKEN embedded in binary

### User flow

1. Install official binary
2. First run: reads ROOT_PUBKEY
3. Creates fm_trust.json signed by root
4. Creates fm_identity.json with fresh seed
5. attested = true

### Encode / decode

- Encode: sign content_hash || size || timestamp
- If attested: set HEADER_FLAG_OFFICIAL_BUILD
- Decode: if flag set -> "OFFICIAL BUILD"

### ZKP protocol

```
Prover (knows seed s, pubkey P):
  k <- random
  R = k*G
  c = SHA512(P || R || file_hash) mod L
  z = (k + c*s) mod L
  publish (P, R, z, file_hash)

Verifier:
  c = SHA512(P || R || file_hash) mod L
  check z*G == R + c*P
```

**Use case:** prove a file is yours without ever exposing the seed.
Even if attacker steals all signed files, they cannot derive the key.

### OTS upgrade

`fm_sign ots <file>` -> `.ots` file (calendar server proof)
`fm_sign ots-upgrade <file>.ots` -> fetch Bitcoin block height

Once Bitcoin-anchored: proof is verifiable forever, independently.

### Attacker scenarios

A. Clone without fm_root.key: BUILD_TOKEN = None, no flag.
B. Attacker own root: real users do not have his root -> Unsigned.
C. Tamper fm_trust.json: sig fails -> fallback to embedded.
D. Patch binary: other users still see Unofficial.
E. Steal signed files: cannot forge without seed; cannot ZKP without scalar.

For binary integrity: code signing (Authenticode / notarization).

## CLI

    fm_status                       Full status
    fm_status --trust               Trust registry
    fm_status --export-root         hex + b64 + fingerprint
    fm_status --export-root-qr q.png
    fm_status --import-root <hex>
    fm_sign add <file> --purpose author --seed <hex64>
    fm_sign tsa <file> [--url URL]
    fm_sign ots <file>
    fm_sign ots-upgrade <file>.ots
    fm_sign zkp-prove  <file> --seed <hex64>
    fm_sign zkp-verify <file> --pubkey H --r H --z H