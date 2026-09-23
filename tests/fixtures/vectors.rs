//! Golden test vectors: deterministic inputs and expected hashes.
//!
//! Purpose: detect regressions in the encode pipeline. If a golden hash
//! changes after a code change, either the change is intentional (update
//! hash) or a bug was introduced.

use sha2::{Digest, Sha256};

pub struct Vector {
    pub name: &'static str,
    pub payload: &'static [u8],
    pub password: &'static str,
}

pub const VECTORS: &[Vector] = &[
    Vector { name: "empty",     payload: b"",                              password: "" },
    Vector { name: "one_byte",  payload: b"a",                             password: "" },
    Vector { name: "hello",     payload: b"Hello, FM Aero Code 2!",       password: "" },
    Vector { name: "password",  payload: b"secret",                        password: "hunter2" },
    Vector { name: "binary_256", payload: &[0u8; 256],                     password: "" },
    Vector { name: "ascii_512", payload: include_bytes!("fixture_ascii_512.bin"), password: "" },
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}