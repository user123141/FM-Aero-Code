//! AeroSeal v1: HKDF + XChaCha20-Poly1305 + HMAC.
//! Encrypt-then-MAC. Optional power-of-2 padding hides size.

use anyhow::{anyhow, Result};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, aead::{Aead, KeyInit, Payload}};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use rand::RngCore;
use zeroize::Zeroizing;
use crate::crypto::kdf::derive_key;
use crate::crypto::SealMode;

type HmacSha256 = Hmac<Sha256>;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 32;



fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("hmac");
    mac.update(info);
    mac.update(&[0x01]);
    let r = mac.finalize().into_bytes();
    let mut o = [0u8; 32];
    o.copy_from_slice(&r);
    o
}

fn quantize_len(n: usize) -> usize {
    if n <= 512 { return n; }
    if n >= 4 * 1024 * 1024 { return n; }
    let mut p = 1024usize;
    while p < n { p *= 2; }
    p
}

pub fn seal(password: &str, plaintext: &[u8], mode: SealMode) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let master = Zeroizing::new(derive_key(password.as_bytes(), &salt));
    let enc_key = Zeroizing::new(hkdf_expand(&master, b"enc"));
    let mac_key = Zeroizing::new(hkdf_expand(&master, b"mac"));

    let mut pt = Vec::with_capacity(4 + plaintext.len() + 512);
    pt.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    pt.extend_from_slice(plaintext);
    if mode == SealMode::Padded {
        let target = quantize_len(pt.len());
        if target > pt.len() { pt.resize(target, 0); }
    }

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"FMAseal1");
    aad.push(mode as u8);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce);

    let cipher = <XChaCha20Poly1305 as KeyInit>::new(Key::from_slice(enc_key.as_ref()));
    let ct = cipher.encrypt(XNonce::from_slice(&nonce),
        Payload { msg: &pt, aad: &aad })
        .map_err(|_| anyhow!("seal encrypt failed"))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(mac_key.as_ref()).expect("hmac");
    mac.update(&salt);
    mac.update(&nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len() + TAG_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn open(password: &str, blob: &[u8]) -> Result<Vec<u8>> {
    let min = SALT_LEN + NONCE_LEN + TAG_LEN + 4;
    if blob.len() < min { return Err(anyhow!("seal: too short")); }
    let salt = &blob[..SALT_LEN];
    let nonce = &blob[SALT_LEN..SALT_LEN+NONCE_LEN];
    let ct = &blob[SALT_LEN+NONCE_LEN..blob.len()-TAG_LEN];
    let tag = &blob[blob.len()-TAG_LEN..];

    let master = Zeroizing::new(derive_key(password.as_bytes(), salt));
    let enc_key = Zeroizing::new(hkdf_expand(&master, b"enc"));
    let mac_key = Zeroizing::new(hkdf_expand(&master, b"mac"));

    let mut mac = <HmacSha256 as Mac>::new_from_slice(mac_key.as_ref()).expect("hmac");
    mac.update(salt);
    mac.update(nonce);
    mac.update(ct);
    let expected = mac.finalize().into_bytes();
    let mut diff = 0u8;
    for i in 0..TAG_LEN { diff |= expected[i] ^ tag[i]; }
    if diff != 0 { return Err(anyhow!("seal: hmac mismatch")); }

    let cipher = <XChaCha20Poly1305 as KeyInit>::new(Key::from_slice(enc_key.as_ref()));
    for m in [SealMode::Plain, SealMode::Padded] {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(b"FMAseal1");
        aad.push(m as u8);
        aad.extend_from_slice(salt);
        aad.extend_from_slice(nonce);
        if let Ok(pt) = cipher.decrypt(XNonce::from_slice(nonce),
            Payload { msg: ct, aad: &aad })
        {
            if pt.len() < 4 { continue; }
            let n = u32::from_le_bytes([pt[0],pt[1],pt[2],pt[3]]) as usize;
            if 4 + n > pt.len() { continue; }
            return Ok(pt[4..4+n].to_vec());
        }
    }
    Err(anyhow!("seal: decrypt failed"))
}

pub fn pattern_fingerprint(password: &str, pattern_id: &[u8; 8]) -> [u8; 8] {
    let master = derive_key(password.as_bytes(), b"FMA-ZKP-v1----");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&master).expect("hmac");
    mac.update(b"pattern-id");
    mac.update(pattern_id);
    let r = mac.finalize().into_bytes();
    let mut o = [0u8; 8];
    o.copy_from_slice(&r[..8]);
    o
}

pub fn pattern_id(content: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"FMA-pid-");
    h.update(content);
    let d = h.finalize();
    let mut o = [0u8; 8];
    o.copy_from_slice(&d[..8]);
    o
}