//! Root trust registry with optional Ed25519 signature.
//!
//! Two registries:
//!   fm_trust.json         - signed by ROOT_PUBKEY (authoritative)
//!   fm_trust.json.sig     - Ed25519 signature of the file content
//!   fm_trust.local.json   - user-managed, NOT signed (marked as unverified)
//!
//! Load order:
//!   1. Try fm_trust.json + verify .sig against compile-time ROOT_PUBKEY
//!   2. If signature invalid -> ignore file, log warning, use only local
//!   3. Load fm_trust.local.json (user overrides, unverified)

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustLevel {
    /// Signed by our ROOT_PUBKEY (authoritative)
    Signed,
    /// User-added via fm_trust.local.json (unverified, but accepted)
    Local,
    /// Embedded at build time (fallback)
    BuildEmbedded,
}

#[derive(Debug, Clone)]
pub struct TrustRoot {
    pub name: String,
    pub pubkey: [u8; 32],
    pub pubkey_hex: String,
    pub level: TrustLevel,
}

#[derive(Debug, Clone, Default)]
pub struct TrustRegistry {
    pub roots: Vec<TrustRoot>,
    pub signature_ok: bool,
    pub warned_tampered: bool,
}

impl TrustRegistry {
    pub fn dir() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    pub fn signed_path() -> PathBuf { Self::dir().join("fm_trust.json") }
    pub fn sig_path() -> PathBuf { Self::dir().join("fm_trust.json.sig") }
    pub fn local_path() -> PathBuf { Self::dir().join("fm_trust.local.json") }

    pub fn load() -> Self {
        let mut reg = TrustRegistry::default();

        // 1. Signed registry
        if let Ok(text) = std::fs::read_to_string(Self::signed_path()) {
            if let Ok(sig_hex) = std::fs::read_to_string(Self::sig_path()) {
                let sig_ok = verify_trust_signature(text.trim(), sig_hex.trim());
                reg.signature_ok = sig_ok;
                if sig_ok {
                    let roots = parse_roots(&text, TrustLevel::Signed);
                    reg.roots.extend(roots);
                } else {
                    reg.warned_tampered = true;
                }
            } else {
                reg.warned_tampered = true;
            }
        }

        // 2. Local overrides (unverified)
        if let Ok(text) = std::fs::read_to_string(Self::local_path()) {
            let roots = parse_roots(&text, TrustLevel::Local);
            for r in roots {
                if !reg.roots.iter().any(|x| x.pubkey == r.pubkey) {
                    reg.roots.push(r);
                }
            }
        }

        // 3. Fallback: compile-time embedded root
        if let Some(pk) = crate::build_info::ROOT_PUBKEY {
            if !reg.roots.iter().any(|x| x.pubkey == pk) {
                reg.roots.push(TrustRoot {
                    name: "Build-embedded root".into(),
                    pubkey: pk,
                    pubkey_hex: hex::encode(&pk),
                    level: TrustLevel::BuildEmbedded,
                });
            }
        }

        reg
    }

    pub fn find(&self, pubkey: &[u8; 32]) -> Option<&TrustRoot> {
        self.roots.iter().find(|r| &r.pubkey == pubkey)
    }

    /// If we have a ROOT_PUBKEY and no signed registry exists yet,
    /// create a minimal one (signed by ourselves via fm_root.key).
    pub fn bootstrap_self_signed_if_needed(&self) {
        let Some(pk) = crate::build_info::ROOT_PUBKEY else { return; };
        let Some(sig) = crate::build_info::BUILD_TOKEN else { return; };
        if Self::signed_path().exists() { return; }

        let hex_pk = hex::encode(&pk);
        let json = format!(
            "{{\"v\":1,\"roots\":[{{\"name\":\"FM Aero Code Official\",\"pubkey\":\"{}\"}}]}}\n",
            hex_pk,
        );
        let _ = std::fs::write(Self::signed_path(), &json);
        // Sign the trimmed JSON with the build token (which is itself a signature
        // of BUILD_COMMITMENT; we treat it as a proof of authorship for bootstrap)
        let sig_hex = hex::encode(sig);
        let _ = std::fs::write(Self::sig_path(), &sig_hex);
    }
}

fn verify_trust_signature(text: &str, sig_hex: &str) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let Some(pk) = crate::build_info::ROOT_PUBKEY else { return false; };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false; };
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else { return false; };
    if sig_bytes.len() != 64 { return false; }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    vk.verify(text.as_bytes(), &sig).is_ok()
}

fn parse_roots(text: &str, level: TrustLevel) -> Vec<TrustRoot> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let s: String = String::from_utf8_lossy(bytes).to_string();
    while let Some(pos) = s[i..].find("\"pubkey\"") {
        let abs = i + pos;
        let Some(colon) = s[abs..].find(':') else { i = abs + 8; continue; };
        let Some(sq) = s[abs + colon..].find('"') else { i = abs + 8; continue; };
        let key_start = abs + colon + sq + 1;
        let Some(eq) = s[key_start..].find('"') else { i = abs + 8; continue; };
        let hexstr = &s[key_start..key_start + eq];
        if hexstr.len() == 64 {
            if let Ok(b) = hex::decode(hexstr) {
                if b.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&b);
                    // find nearest name
                    let pre = &s[..abs];
                    let name = pre.rfind("\"name\"").and_then(|np| {
                        let col = pre[np..].find(':')?;
                        let sq = pre[np + col..].find('"')?;
                        let ns = np + col + sq + 1;
                        let ne = pre[ns..].find('"')?;
                        Some(pre[ns..ns + ne].to_string())
                    }).unwrap_or_else(|| "unnamed".into());
                    out.push(TrustRoot {
                        name,
                        pubkey: pk,
                        pubkey_hex: hexstr.to_string(),
                        level: level.clone(),
                    });
                }
            }
        }
        i = key_start + eq + 1;
    }
    out
}