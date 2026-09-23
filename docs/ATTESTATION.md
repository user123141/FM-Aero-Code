# Attestation - how FM Aero Code proves authorship

## The problem

Anyone can git clone, compile, produce files that look identical to official
FM Aero Code output. We need a way to verify "was this made by the real app,
or by a fork?"

## The scheme (Embedded Root Seed)

### Files

| File | Owner | Purpose |
|---|---|---|
| fm_root.key | author (gitignored) | 32-byte Ed25519 seed |
| ROOT_PUBKEY | embedded at build | 32-byte pubkey |
| BUILD_TOKEN | embedded at build | 64-byte signature |
| fm_trust.json | author (public) | Trusted roots; signed |
| fm_trust.json.sig | author (public) | Ed25519 sig of fm_trust.json |
| fm_trust.local.json | user | User-added roots (unverified) |
| fm_identity.json | per-install | Local Ed25519 seed |

### Author flow

1. fm_root.key in repo (gitignored)
2. cargo build runs build.rs
3. build.rs reads fm_root.key, signs 32-byte commitment
4. Embeds ROOT_PUBKEY + BUILD_TOKEN in binary

### User flow

1. Download official binary
2. First run: reads embedded ROOT_PUBKEY
3. Creates fm_trust.json signed by root
4. Creates fm_identity.json with fresh per-install seed
5. attested = true

### Encode / decode

Encode: sign content_hash || size || timestamp.
If attested: sets HEADER_FLAG_OFFICIAL_BUILD.

Decode: if flag set -> "OFFICIAL BUILD" badge.

### Attacker scenarios

A. Clone without fm_root.key: BUILD_TOKEN = None, no flag.
B. Attacker own root: real users don't have his root in trust -> Unsigned.
C. Tamper fm_trust.json: signature fails -> fallback to embedded.
D. Patch binary: other users still see Unofficial.

For binary integrity: code signing (Authenticode / notarization).

## Edit the JSON files?

fm_trust.json is signed - don't edit. Use fm_trust.local.json for additions:

    {
      "roots": [
        { "name": "My Company", "pubkey": "a3f2b1c8e4d5..." }
      ]
    }

## Do I have to do anything?

No. Automatic.
- Author: generate fm_root.key once
- User: install binary, first run creates identity + trust
- Encode: automatic signing
- Decode: automatic verification

## CLI

    fm_status                       Full status
    fm_status --trust               Trust registry
    fm_status --identity            This install
    fm_status --export-root         hex + b64 + fingerprint
    fm_status --export-root-qr q.png
    fm_status --import-root <hex>
    fm_status --fingerprint <hex>