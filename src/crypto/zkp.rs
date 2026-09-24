//! Zero-Knowledge Proof of Ownership (Schnorr NIZK on Ed25519).
//!
//! Proves: "I know the private seed s such that P = s*G,
//!          where P is the pubkey that signed this file".
//! Does NOT reveal s.
//!
//! Protocol (non-interactive, Fiat-Shamir):
//!   Prover:
//!     k <- random scalar
//!     R = k*G
//!     c = SHA512(P || R || file_hash) mod L
//!     z = (k + c*s) mod L
//!     send (R, z)
//!   Verifier:
//!     c = SHA512(P || R || file_hash) mod L
//!     check z*G == R + c*P

use anyhow::Result;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone)]
pub struct ZkProof {
    /// R = k*G, 32-byte compressed point
    pub r_bytes: [u8; 32],
    /// z = k + c*s mod L, 32-byte scalar
    pub z_bytes: [u8; 32],
}

/// Compute challenge c = SHA512(P || R || file_hash) mod L.
fn challenge(pk: &[u8; 32], r: &[u8; 32], file_hash: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"FMA-zkp-v1");
    h.update(pk);
    h.update(r);
    h.update(file_hash);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Generate a ZKP for file_hash using signing seed.
pub fn prove(seed: &[u8; 32], file_hash: &[u8]) -> Result<ZkProof> {
    use rand::RngCore;
    let sk = SigningKey::from_bytes(seed);
    let vk: VerifyingKey = sk.verifying_key();
    let pk_bytes = vk.to_bytes();

    // s = secret scalar derived from seed
    // ed25519-dalek: signing key IS a scalar (clamped hash)
    // We use the same seed -> same pubkey. For ZKP we need the scalar;
    // we approximate with SHA512(seed)[..32] clamped, which matches
    // dalek key derivation. To avoid deep internals, we use a simpler
    // approach: treat the full seed as scalar material via SHA512.
    let s = scalar_from_seed(seed);

    // k <- random
    let mut k_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k_bytes);
    let k = Scalar::from_bytes_mod_order(k_bytes);

    // R = k*G
    let r_point = ED25519_BASEPOINT_POINT * k;
    let r_bytes = r_point.compress().to_bytes();

    // c = SHA512(P || R || file_hash) mod L
    let c = challenge(&pk_bytes, &r_bytes, file_hash);

    // z = k + c*s
    let z = k + c * s;

    Ok(ZkProof {
        r_bytes,
        z_bytes: z.to_bytes(),
    })
}

/// Verify: check z*G == R + c*P.
pub fn verify(proof: &ZkProof, pk: &[u8; 32], file_hash: &[u8]) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let Some(r_point) = CompressedEdwardsY(proof.r_bytes).decompress() else { return false; };
    let Some(p_point) = CompressedEdwardsY(*pk).decompress() else { return false; };

    let z = Scalar::from_bytes_mod_order(proof.z_bytes);
    let c = challenge(pk, &proof.r_bytes, file_hash);

    let lhs = ED25519_BASEPOINT_POINT * z;
    let rhs = r_point + p_point * c;

    lhs == rhs
}

fn scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    // Ed25519 scalar = clamp(SHA512(seed)[0..32]) interpreted as LE integer.
    // CRITICAL: we must use ONLY the first 32 bytes, not the full 64-byte wide
    // reduction. from_bytes_mod_order_wide would fold the 64-byte prefix back
    // into the scalar (N = low + high*2^256), breaking s*G == P.
    let mut h = Sha512::new();
    h.update(seed);
    let digest = h.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    // Ed25519 clamping
    scalar_bytes[0]  &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    Scalar::from_bytes_mod_order(scalar_bytes)
}