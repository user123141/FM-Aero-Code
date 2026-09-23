use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

pub fn sign_header(sk: &SigningKey, header_bytes: &[u8]) -> [u8; 64] {
    let sig: Signature = sk.sign(header_bytes);
    sig.to_bytes()
}

pub fn verify_header(vk: &VerifyingKey, header_bytes: &[u8], sig_bytes: &[u8; 64]) -> bool {
    let sig = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(header_bytes, &sig).is_ok()
}