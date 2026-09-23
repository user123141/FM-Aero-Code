//! Argon2id key derivation.
//!
//! CRITICAL: parameters MUST be identical on every platform (native,
//! WASM, mobile). If they differ, the same password produces different
//! keys on different machines, and cross-platform decryption breaks.
//!
//! Chosen: 32 MiB memory, 3 iterations, 2 lanes.
//! Meets OWASP 2025 minimum (19 MiB / t=2 / p=1).
//! Runs ~300ms on modern phones (WASM), ~80ms on desktop.

use argon2::{Argon2, Algorithm, Version, Params};

pub const MEM_KIB: u32 = 32 * 1024;
pub const ITER: u32 = 3;
pub const PAR: u32 = 2;
pub const KEY_LEN: usize = 32;

pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let params = Params::new(MEM_KIB, ITER, PAR, Some(KEY_LEN)).expect("static");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut out).expect("ok");
    out
}

pub fn params() -> (u32, u32, u32) { (MEM_KIB, ITER, PAR) }
