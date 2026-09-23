//! AeroSeal v2: X25519 ephemeral + HKDF + XChaCha20-Poly1305 + HMAC.
//! Supports single and multi-recipient modes.

use anyhow::{anyhow, Result};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce, aead::{Aead, KeyInit, Payload}};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use crate::crypto::SealMode;

type HmacSha256 = Hmac<Sha256>;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 32;
const EPH_PUB_LEN: usize = 32;
const RECIPIENT_ID_LEN: usize = 8;



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

/// 8-byte public recipient ID (SHA-256 prefix).
pub fn recipient_id(pk: &PublicKey) -> [u8; RECIPIENT_ID_LEN] {
    let mut h = Sha256::new();
    h.update(b"FMA-rid-");
    h.update(pk.as_bytes());
    let d = h.finalize();
    let mut o = [0u8; RECIPIENT_ID_LEN];
    o.copy_from_slice(&d[..RECIPIENT_ID_LEN]);
    o
}

pub struct RecipientKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

pub fn generate_recipient() -> RecipientKeypair {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    RecipientKeypair { secret, public }
}

pub fn recipient_from_seed(seed: [u8; 32]) -> RecipientKeypair {
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    RecipientKeypair { secret, public }
}

/// Encrypt for ONE recipient. Returns block without recipient ID.
fn seal_v2_block(recipient: &PublicKey, plaintext: &[u8], mode: SealMode) -> Result<Vec<u8>> {
    let eph_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(recipient);

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut master = [0u8; 32];
    {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(shared.as_bytes()).expect("hmac");
        mac.update(&salt);
        mac.update(&[0x01]);
        let r = mac.finalize().into_bytes();
        master.copy_from_slice(&r);
    }
    let enc_key = hkdf_expand(&master, b"enc2");
    let mac_key = hkdf_expand(&master, b"mac2");

    let mut pt = Vec::with_capacity(4 + plaintext.len() + 512);
    pt.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    pt.extend_from_slice(plaintext);
    if mode == SealMode::Padded {
        let target = quantize_len(pt.len());
        if target > pt.len() { pt.resize(target, 0); }
    }

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(b"FMAseal2");
    aad.push(mode as u8);
    aad.extend_from_slice(eph_public.as_bytes());
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&nonce);

    let cipher = <XChaCha20Poly1305 as KeyInit>::new(Key::from_slice(&enc_key));
    let ct = cipher.encrypt(XNonce::from_slice(&nonce),
        Payload { msg: &pt, aad: &aad })
        .map_err(|_| anyhow!("seal2 encrypt failed"))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("hmac");
    mac.update(eph_public.as_bytes());
    mac.update(&salt);
    mac.update(&nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(EPH_PUB_LEN + SALT_LEN + NONCE_LEN + ct.len() + TAG_LEN);
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Single recipient.
pub fn seal_v2(recipient: &PublicKey, plaintext: &[u8], mode: SealMode) -> Result<Vec<u8>> {
    seal_v2_block(recipient, plaintext, mode)
}

/// Multi-recipient: encrypt plaintext N times, one block per recipient.
/// Format: [count: u16 LE] { [rid: 8] [block_len: u32 LE] [block] } * count
pub fn seal_v2_multi(recipients: &[PublicKey], plaintext: &[u8], mode: SealMode) -> Result<Vec<u8>> {
    if recipients.is_empty() { return Err(anyhow!("no recipients")); }
    if recipients.len() > 32 { return Err(anyhow!("max 32 recipients")); }
    let mut out = Vec::new();
    out.extend_from_slice(&(recipients.len() as u16).to_le_bytes());
    for pk in recipients {
        let rid = recipient_id(pk);
        let block = seal_v2_block(pk, plaintext, mode)?;
        out.extend_from_slice(&rid);
        out.extend_from_slice(&(block.len() as u32).to_le_bytes());
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// Decrypt single-recipient block.
pub fn open_v2(recipient_secret: &StaticSecret, blob: &[u8]) -> Result<Vec<u8>> {
    open_v2_block(recipient_secret, blob)
}

fn open_v2_block(recipient_secret: &StaticSecret, blob: &[u8]) -> Result<Vec<u8>> {
    let min = EPH_PUB_LEN + SALT_LEN + NONCE_LEN + TAG_LEN + 4;
    if blob.len() < min { return Err(anyhow!("seal2: too short")); }
    let eph_pub_bytes: [u8; 32] = blob[..EPH_PUB_LEN].try_into().unwrap();
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let salt = &blob[EPH_PUB_LEN..EPH_PUB_LEN+SALT_LEN];
    let nonce = &blob[EPH_PUB_LEN+SALT_LEN..EPH_PUB_LEN+SALT_LEN+NONCE_LEN];
    let ct = &blob[EPH_PUB_LEN+SALT_LEN+NONCE_LEN..blob.len()-TAG_LEN];
    let tag = &blob[blob.len()-TAG_LEN..];

    let shared = recipient_secret.diffie_hellman(&eph_pub);
    let mut master = [0u8; 32];
    {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(shared.as_bytes()).expect("hmac");
        mac.update(salt);
        mac.update(&[0x01]);
        let r = mac.finalize().into_bytes();
        master.copy_from_slice(&r);
    }
    let enc_key = hkdf_expand(&master, b"enc2");
    let mac_key = hkdf_expand(&master, b"mac2");

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("hmac");
    mac.update(&eph_pub_bytes);
    mac.update(salt);
    mac.update(nonce);
    mac.update(ct);
    let expected = mac.finalize().into_bytes();
    let mut diff = 0u8;
    for i in 0..TAG_LEN { diff |= expected[i] ^ tag[i]; }
    if diff != 0 { return Err(anyhow!("seal2: hmac mismatch")); }

    let cipher = <XChaCha20Poly1305 as KeyInit>::new(Key::from_slice(&enc_key));
    for m in [SealMode::Plain, SealMode::Padded] {
        let mut aad = Vec::with_capacity(96);
        aad.extend_from_slice(b"FMAseal2");
        aad.push(m as u8);
        aad.extend_from_slice(&eph_pub_bytes);
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
    Err(anyhow!("seal2: decrypt failed"))
}

/// Multi-recipient: find our block via recipient_id, then decrypt.
pub fn open_v2_multi(recipient_secret: &StaticSecret, recipient_public: &PublicKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 2 { return Err(anyhow!("seal2-multi: too short")); }
    let count = u16::from_le_bytes([blob[0], blob[1]]) as usize;
    if count == 0 || count > 32 { return Err(anyhow!("bad recipient count")); }
    let our_id = recipient_id(recipient_public);
    let mut pos = 2usize;
    for _ in 0..count {
        if pos + RECIPIENT_ID_LEN + 4 > blob.len() { return Err(anyhow!("truncated")); }
        let rid = &blob[pos..pos+RECIPIENT_ID_LEN];
        let blen = u32::from_le_bytes([
            blob[pos+RECIPIENT_ID_LEN],
            blob[pos+RECIPIENT_ID_LEN+1],
            blob[pos+RECIPIENT_ID_LEN+2],
            blob[pos+RECIPIENT_ID_LEN+3],
        ]) as usize;
        pos += RECIPIENT_ID_LEN + 4;
        if pos + blen > blob.len() { return Err(anyhow!("block truncated")); }
        let block = &blob[pos..pos+blen];
        if rid == our_id {
            return open_v2_block(recipient_secret, block);
        }
        pos += blen;
    }
    Err(anyhow!("not a recipient"))
}