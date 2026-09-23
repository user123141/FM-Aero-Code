//! Per-install Ed25519 identity + root attestation.
//!
//! File: fm_identity.json (next to exe, first run).
//! Contains: seed (hex 64) + pubkey (hex 64).

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::PathBuf;

#[derive(Clone)]
pub struct AppIdentity {
    pub seed: [u8; 32],
    pub pubkey: [u8; 32],
    pub root_pubkey: Option<[u8; 32]>,
    pub attested: bool,
    pub attester_name: Option<String>,
}

impl AppIdentity {
    pub fn path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("fm_identity.json")))
            .unwrap_or_else(|| PathBuf::from("fm_identity.json"))
    }

    pub fn load_or_create() -> Result<Self> {
        crate::trust::TrustRegistry::load().bootstrap_self_signed_if_needed();

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
        let json = format!(
            "{{\"seed\":\"{}\",\"pubkey\":\"{}\"}}\n",
            hex::encode(&id.seed),
            hex::encode(&id.pubkey)
        );
        let _ = std::fs::write(&path, json);
        Ok(id)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(vk.as_bytes());

        let root_pubkey = crate::build_info::ROOT_PUBKEY;
        let (attested, attester_name) = if let Some(rpk) = root_pubkey.as_ref() {
            let reg = crate::trust::TrustRegistry::load();
            match reg.find(rpk) {
                Some(r) => {
                    let ok = matches!(
                        r.level,
                        crate::trust::TrustLevel::Signed
                            | crate::trust::TrustLevel::BuildEmbedded
                    );
                    (ok, Some(r.name.clone()))
                }
                None => (false, None),
            }
        } else {
            (false, None)
        };

        Self {
            seed,
            pubkey: pk,
            root_pubkey,
            attested,
            attester_name,
        }
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.seed);
        sk.sign(data).to_bytes()
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(&self.pubkey)
    }

    pub fn pubkey_b64(&self) -> String {
        pubkey_b64(&self.pubkey)
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.pubkey)
    }

    pub fn verify_with_own(&self, data: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.pubkey) else {
            return false;
        };
        let s = Signature::from_bytes(sig);
        vk.verify(data, &s).is_ok()
    }
}

fn parse_seed(text: &str) -> Option<[u8; 32]> {
    let needle = "\"seed\":\"";
    let start = text.find(needle)? + needle.len();
    let rest = &text[start..];
    let quote_idx = rest.find('"')?;
    let hexstr = &rest[..quote_idx];
    let bytes = hex::decode(hexstr).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// SHA-256(pubkey)[:8] formatted ABCD-EF01-2345-6789.
pub fn fingerprint(pubkey: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pubkey);
    let d = h.finalize();
    format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// Base64 of pubkey (44 chars).
pub fn pubkey_b64(pubkey: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(pubkey)
}

/// Parse either hex (64 chars) or base64 (~44 chars).
pub fn parse_pubkey(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() == 64 {
        if let Ok(b) = hex::decode(s) {
            if b.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                return Some(out);
            }
        }
    }
    use base64::Engine;
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
        if b.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            return Some(out);
        }
    }
    None
}

/// Message format that app-identity signs.
pub fn app_signed_message(content_hash: &[u8; 8], original_size: u32, timestamp: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(16);
    m.extend_from_slice(content_hash);
    m.extend_from_slice(&original_size.to_le_bytes());
    m.extend_from_slice(&timestamp.to_le_bytes());
    m
}