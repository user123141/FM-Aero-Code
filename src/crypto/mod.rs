pub mod kdf;
pub mod hash;
pub mod sign;
pub mod seal;
pub mod seal2;

pub use hash::{sha256_short, content_hash_8, content_hash_6, constant_time_eq, hmac_sha256};
pub use sign::{sign_header, verify_header, generate_keypair, keypair_from_seed};
pub use seal::{seal, open, pattern_fingerprint, pattern_id};
pub use seal2::{
    seal_v2, seal_v2_multi, open_v2, open_v2_multi,
    generate_recipient, recipient_from_seed, recipient_id, RecipientKeypair,
};

pub const AEAD_NONCE_LEN: usize = 12;
pub const XAEAD_NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

/// Unified seal mode, shared between AeroSeal v1 and v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealMode { Plain, Padded }
impl Default for SealMode { fn default() -> Self { Self::Padded } }

/// Cipher selector. Only two real ciphers + None.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    None   = 0,
    SealV1 = 1,
    SealV2 = 2,
}

impl CipherKind {
    pub fn from_byte(b: u8) -> Self {
        match b { 1 => Self::SealV1, 2 => Self::SealV2, _ => Self::None }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::None   => "none",
            Self::SealV1 => "AeroSeal v1",
            Self::SealV2 => "AeroSeal v2",
        }
    }
    pub fn is_none(&self) -> bool { *self == Self::None }
}