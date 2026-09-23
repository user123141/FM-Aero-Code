use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

pub fn content_hash_8(d: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new(); h.update(d);
    let full = h.finalize();
    let mut o = [0u8; 8]; o.copy_from_slice(&full[..8]); o
}
pub fn content_hash_6(d: &[u8]) -> [u8; 6] {
    let h8 = content_hash_8(d);
    let mut o = [0u8; 6]; o.copy_from_slice(&h8[..6]); o
}
pub fn sha256_short(d: &[u8]) -> String { hex::encode(content_hash_8(d)) }

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut o = [0u8; 32];
    o.copy_from_slice(&result);
    o
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut x = 0u8; for i in 0..a.len() { x |= a[i] ^ b[i]; } x == 0
}