//! Per-install Ed25519 identity ("publisher key").
//!
//! On first run we generate a 32-byte seed and save it to fm_identity.json
//! next to the executable. Every encode signs the payload hash + timestamp
//! with this key. On decode we verify: if the signature matches OUR pubkey,
//! the file was produced by this install of FM Aero Code.
//!
//! This is the basis for anti-forgery: an attacker who does not have the
//! private seed cannot produce a file that verifies as "made by us".

use anyhow::Result;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use std::path::PathBuf;

#[derive(Clone)]
pub struct AppIdentity {
    pub seed: [u8; 32],
    pub pubkey: [u8; 32],
}

impl AppIdentity {
    pub fn path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("fm_identity.json")))
            .unwrap_or_else(|| PathBuf::from("fm_identity.json"))
    }

    pub fn load_or_create() -> Result<Self> {
        let path = Self::path();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(seed) = parse_seed(&text) {
                return Ok(Self::from_seed(seed));
            }
        }
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let id = Self::from_seed(seed);
        let json = format!("{{\"seed\":\"{}\",\"pubkey\":\"{}\"}}\n",
            hex::encode(&id.seed), hex::encode(&id.pubkey));
        let _ = std::fs::write(&path, json);
        Ok(id)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(vk.as_bytes());
        Self { seed, pubkey: pk }
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.seed);
        sk.sign(data).to_bytes()
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(&self.pubkey)
    }

    pub fn verify_with_own(&self, data: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.pubkey) else { return false; };
        let s = Signature::from_bytes(sig);
        vk.verify(data, &s).is_ok()
    }
}

fn parse_seed(text: &str) -> Option<[u8; 32]> {
    let needle = "\"seed\":\"";
    let start = text.find(needle)? + needle.len();
    let end = text[start..].find('"')? + start;
    let bytes = hex::decode(&text[start..end]).ok()?;
    if bytes.len() != 32 { return None; }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Canonical byte string that we sign / verify. Anything that changes
/// (hash, size, timestamp) invalidates the signature.
pub fn app_signed_message(content_hash: &[u8; 8], original_size: u32, timestamp: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(16);
    m.extend_from_slice(content_hash);
    m.extend_from_slice(&original_size.to_le_bytes());
    m.extend_from_slice(&timestamp.to_le_bytes());
    m
}