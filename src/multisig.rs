//! Multi-signature extension block (FMEX).
//!
//! Stream layout: [AeroHeader 128][FMEX block?][payload]
//!
//! FMEX block:
//!   [0x46 0x4D 0x45 0x58]  "FMEX"
//!   [version u8 = 1]
//!   [flags u8 = 0]
//!   [json_len u16 LE]
//!   [json_len bytes JSON]
//!
//! JSON structure:
//!   {
//!     "signatures": [
//!       {"purpose": "author", "pubkey": "hex64", "sig": "hex128"},
//!       {"purpose": "validator", "pubkey": "hex64", "sig": "hex128"}
//!     ],
//!     "tsa": {"server": "...", "token_b64": "..."},
//!     "anchor": {"chain": "bitcoin", "tx": "..."}
//!   }
//!
//! Decoder: if stream[128..132] == b"FMEX", parse ext, then read payload.
//! Backward compatible: old files have no FMEX; new decoders handle both.

use anyhow::{anyhow, Result};

pub const FMEX_MAGIC: [u8; 4] = *b"FMEX";
pub const FMEX_VERSION: u8 = 1;
pub const FMEX_MIN_HEADER: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct ExtraSignature {
    pub purpose: String,      // "author", "validator", "witness", ...
    pub pubkey_hex: String,   // 64 hex chars
    pub sig_hex: String,      // 128 hex chars
}

#[derive(Debug, Clone, Default)]
pub struct MultiSigBlock {
    pub signatures: Vec<ExtraSignature>,
    pub tsa_server: Option<String>,
    pub tsa_token_b64: Option<String>,
    pub anchor_chain: Option<String>,
    pub anchor_tx: Option<String>,
}

impl MultiSigBlock {
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
            && self.tsa_server.is_none()
            && self.anchor_chain.is_none()
    }

    pub fn to_json(&self) -> String {
        let mut s = String::from("{\n");
        let mut first_top = true;

        if !self.signatures.is_empty() {
            s.push_str("  \"signatures\": [");
            for (i, sig) in self.signatures.iter().enumerate() {
                if i > 0 { s.push(','); }
                s.push_str(&format!(
                    "\n    {{\"purpose\":\"{}\",\"pubkey\":\"{}\",\"sig\":\"{}\"}}",
                    escape_json(&sig.purpose), sig.pubkey_hex, sig.sig_hex
                ));
            }
            s.push_str("\n  ]");
            first_top = false;
        }

        if let (Some(server), Some(token)) = (&self.tsa_server, &self.tsa_token_b64) {
            if !first_top { s.push(','); }
            s.push_str(&format!(
                "\n  \"tsa\": {{\"server\":\"{}\",\"token_b64\":\"{}\"}}",
                escape_json(server), escape_json(token)
            ));
            first_top = false;
        }

        if let (Some(chain), Some(tx)) = (&self.anchor_chain, &self.anchor_tx) {
            if !first_top { s.push(','); }
            s.push_str(&format!(
                "\n  \"anchor\": {{\"chain\":\"{}\",\"tx\":\"{}\"}}",
                escape_json(chain), escape_json(tx)
            ));
        }

        s.push_str("\n}");
        s
    }

    pub fn from_json(text: &str) -> Self {
        let mut out = MultiSigBlock::default();
        // Simple parser: extract signature entries
        let mut i = 0usize;
        while let Some(p) = text[i..].find("\"purpose\"") {
            let abs = i + p;
            let purpose = extract_str(text, abs, "purpose").unwrap_or_default();
            let pubkey = extract_str(text, abs, "pubkey").unwrap_or_default();
            let sig = extract_str(text, abs, "sig").unwrap_or_default();
            if !pubkey.is_empty() && !sig.is_empty() {
                out.signatures.push(ExtraSignature { purpose, pubkey_hex: pubkey, sig_hex: sig });
            }
            i = abs + 10;
        }
        out.tsa_server = extract_str_anywhere(text, "server");
        out.tsa_token_b64 = extract_str_anywhere(text, "token_b64");
        out.anchor_chain = extract_str_anywhere(text, "chain");
        out.anchor_tx = extract_str_anywhere(text, "tx");
        out
    }

    pub fn encode_block(&self) -> Vec<u8> {
        let json = self.to_json();
        let jlen = json.len().min(65535);
        let mut out = Vec::with_capacity(8 + jlen);
        out.extend_from_slice(&FMEX_MAGIC);
        out.push(FMEX_VERSION);
        out.push(0);
        out.extend_from_slice(&(jlen as u16).to_le_bytes());
        out.extend_from_slice(&json.as_bytes()[..jlen]);
        out
    }

    pub fn decode_block(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < FMEX_MIN_HEADER {
            return Err(anyhow!("FMEX: too short"));
        }
        if &data[0..4] != &FMEX_MAGIC {
            return Err(anyhow!("FMEX: bad magic"));
        }
        let ver = data[4];
        if ver != FMEX_VERSION {
            return Err(anyhow!("FMEX: version {} not supported", ver));
        }
        let jlen = u16::from_le_bytes([data[6], data[7]]) as usize;
        if data.len() < FMEX_MIN_HEADER + jlen {
            return Err(anyhow!("FMEX: truncated JSON"));
        }
        let json = String::from_utf8_lossy(&data[FMEX_MIN_HEADER..FMEX_MIN_HEADER + jlen]).to_string();
        Ok((Self::from_json(&json), FMEX_MIN_HEADER + jlen))
    }
}

fn escape_json(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o
}

fn extract_str(text: &str, from: usize, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let window = &text[from..];
    let pos = window.find(&needle)?;
    let after = &window[pos + needle.len()..];
    let colon = after.find(':')?;
    let rest = &after[colon + 1..];
    let start_quote = rest.find('"')?;
    let content = &rest[start_quote + 1..];
    let end_quote = content.find('"')?;
    Some(content[..end_quote].to_string())
}

fn extract_str_anywhere(text: &str, key: &str) -> Option<String> {
    extract_str(text, 0, key)
}

/// Sign a stream (header+payload) and produce a signature entry.
pub fn make_author_signature(stream: &[u8], seed: &[u8; 32], purpose: &str) -> ExtraSignature {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(seed);
    let vk = sk.verifying_key();
    let sig = sk.sign(stream).to_bytes();
    ExtraSignature {
        purpose: purpose.to_string(),
        pubkey_hex: hex::encode(vk.as_bytes()),
        sig_hex: hex::encode(sig),
    }
}

pub fn verify_signature(stream: &[u8], sig: &ExtraSignature) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let Ok(pk_bytes) = hex::decode(&sig.pubkey_hex) else { return false; };
    if pk_bytes.len() != 32 { return false; }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false; };
    let Ok(sig_bytes) = hex::decode(&sig.sig_hex) else { return false; };
    if sig_bytes.len() != 64 { return false; }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&arr);
    vk.verify(stream, &signature).is_ok()
}