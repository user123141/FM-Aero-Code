//! Build-time root attestation.
//!
//! Reads fm_root.key (32-byte hex Ed25519 seed, gitignored).
//! If present: signs BUILD_COMMITMENT (exactly 32 bytes) with the key,
//! embeds ROOT_PUBKEY (32B) + BUILD_TOKEN (64B) in the binary.
//! If fm_root.key absent: embeds None (unauthorized build).

use std::fs;
use std::path::Path;

// Exactly 32 bytes. Written as an array literal to avoid length miscounts.
// Represents the string "FM-Aero-Code-Official-Build-v1!!"
const COMMITMENT: [u8; 32] = [
    b'F', b'M', b'-', b'A', b'e', b'r', b'o', b'-',
    b'C', b'o', b'd', b'e', b'-', b'O', b'f', b'f',
    b'i', b'c', b'i', b'a', b'l', b'-', b'B', b'u',
    b'i', b'l', b'd', b'-', b'v', b'1', b'!', b'!',
];

fn main() {
    println!("cargo:rerun-if-changed=fm_root.key");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("generated_build_token.rs");

    let code = match fs::read_to_string("fm_root.key") {
        Ok(hex_str) => match hex::decode(hex_str.trim()) {
            Ok(seed) if seed.len() == 32 => {
                use ed25519_dalek::{Signer, SigningKey};
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&seed);
                let sk = SigningKey::from_bytes(&arr);
                let vk = sk.verifying_key();
                let sig = sk.sign(&COMMITMENT).to_bytes();
                let pubkey = vk.to_bytes();
                let pk_hex = hex::encode(pubkey);
                let sig_hex = hex::encode(sig);
                format!(
                    "pub const ROOT_PUBKEY: Option<[u8; 32]> = Some({:?});\n\
                     pub const BUILD_TOKEN: Option<[u8; 64]> = Some({:?});\n\
                     pub const ROOT_PUBKEY_HEX: Option<&'static str> = Some(\"{}\");\n\
                     pub const BUILD_TOKEN_HEX: Option<&'static str> = Some(\"{}\");\n",
                    pubkey, sig, pk_hex, sig_hex
                )
            }
            _ => empty_token(),
        },
        Err(_) => empty_token(),
    };

    fs::write(out_path, code).unwrap();
}

fn empty_token() -> String {
    "pub const ROOT_PUBKEY: Option<[u8; 32]> = None;\n\
     pub const BUILD_TOKEN: Option<[u8; 64]> = None;\n\
     pub const ROOT_PUBKEY_HEX: Option<&'static str> = None;\n\
     pub const BUILD_TOKEN_HEX: Option<&'static str> = None;\n"
        .to_string()
}