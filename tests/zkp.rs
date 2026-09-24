//! ZKP round-trip tests. Regression guard for scalar_from_seed.
//!
//! Before v3.16.0, scalar_from_seed used from_bytes_mod_order_wide on the
//! full 64-byte SHA512 output, giving a scalar that did NOT match the
//! Ed25519 keypair. Every proof silently verified as INVALID. These tests
//! catch that class of bug.

use fm_aero_code_2::crypto::{zkp_prove, zkp_verify};
use ed25519_dalek::SigningKey;

#[test]
fn zkp_roundtrip_valid() {
    let seed = [0x42u8; 32];
    let file_hash = b"FM Aero Code 2 - ZKP test vector - 32 bytes!!";
    let proof = zkp_prove(&seed, file_hash).expect("prove");
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    assert!(
        zkp_verify(&proof, &vk.to_bytes(), file_hash),
        "ZKP round-trip failed - scalar_from_seed likely broken"
    );
}

#[test]
fn zkp_wrong_key_rejected() {
    let seed = [0x42u8; 32];
    let other = [0x43u8; 32];
    let file_hash = b"same file hash";
    let proof = zkp_prove(&seed, file_hash).expect("prove");
    let vk_other = SigningKey::from_bytes(&other).verifying_key();
    assert!(
        !zkp_verify(&proof, &vk_other.to_bytes(), file_hash),
        "ZKP accepted a proof under the wrong pubkey"
    );
}

#[test]
fn zkp_wrong_hash_rejected() {
    let seed = [0x42u8; 32];
    let proof = zkp_prove(&seed, b"hash A").expect("prove");
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    assert!(
        !zkp_verify(&proof, &vk.to_bytes(), b"hash B"),
        "ZKP accepted a proof for a different file hash"
    );
}

#[test]
fn zkp_public_key_matches_signing_key() {
    // Ensure the pubkey we publish matches the Ed25519 keypair for the seed
    // (this is the exact relationship ZKP depends on).
    let seed = [0x42u8; 32];
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    let proof = zkp_prove(&seed, b"any").expect("prove");
    // Proof must verify against vk
    assert!(zkp_verify(&proof, &vk.to_bytes(), b"any"));
    // And it must NOT verify against a different key
    let vk2 = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key();
    assert!(!zkp_verify(&proof, &vk2.to_bytes(), b"any"));
}