# FM Aero Code 2 - Security Model

## Cryptographic primitives

### AeroSeal v1 (password-based symmetric)

KDF: Argon2id (32 MiB, t=3, p=2). AEAD: XChaCha20-Poly1305 with 24-byte
random nonce. MAC: HMAC-SHA256 over salt, nonce, ciphertext (encrypt-then-MAC).
Wire: salt[16] + nonce[24] + ciphertext + tag[32].

### AeroSeal v2 (recipient asymmetric)

Ephemeral X25519 per message. HKDF derives enc/mac keys from shared secret.
Recipient ID = SHA-256(public_key)[:8]. Multi-recipient envelope:
count[2] + (rid[8] + len[4] + block)*count.

## Threat model

### In scope

* Attacker has the pattern but no password:
  - Password recovery requires breaking 256-bit XChaCha20-Poly1305.
  - Brute-force is bounded by Argon2id (32 MiB per guess).
  - Pattern tampering is detected by HMAC.

### Out of scope

* Side-channel attacks on the encoder machine.
* Physical access with password in RAM.
* Quantum computers (X25519, Ed25519 are not PQ-safe).
* Supply-chain attacks on Rust toolchain or crates.io.

### Known limitations

* Decompression bombs: mitigated via MAX_DECOMPRESSED_BYTES = 512 MiB.
* Header forgery without password: flags are not MACed when cipher is None.
* Pattern fingerprint leakage: identical patterns correlate.
* Argon2id params are fixed. Changing them breaks old patterns.

## Cryptographic dependencies

* chacha20poly1305 0.10 (RustCrypto, constant-time)
* argon2 0.5 (RustCrypto, side-channel resistant)
* x25519-dalek 2, ed25519-dalek 2 (dalek-cryptography, audited)
* sha2 0.10, hmac 0.12 (RustCrypto)
* zeroize 1.8 (memory scrubbing)

## No-unsafe policy

The crate is #![forbid(unsafe_code)]. Transitive dependencies may contain
audited unsafe for performance (dalek, RustCrypto).

## Reporting

Report vulnerabilities privately. Do not open public issues for security.
