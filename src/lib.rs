#![allow(dead_code)]
#![forbid(unsafe_code)]

//! FM Aero Code 2 - Fast Memory optical storage.
//!
//! Encodes any file into a printable black-and-white pattern.
//! Uses FFT-based OFDM transport (AeroGlint Spectrum Protocol).
//!
//! Also provides:
//!   - Steganography (LSB / DCT-QIM / DualB)
//!   - Layered encoding (AeroGlint + Stego in one image)
//!   - Per-install Ed25519 identity + root attestation
//!   - Multi-signature blocks (FMEX)

pub mod error;
pub mod types;
pub mod fastmem;
pub mod settings;
pub mod fec;
pub mod resilience;
pub mod selftest;
pub mod crypto;
pub mod encoder;
pub mod decoder;
pub mod steganography;
pub mod audio;
pub mod layered;
pub mod identity;
pub mod trust;
pub mod multisig;
pub mod tsa;

#[cfg(feature = "gui")]
pub mod app;
#[cfg(feature = "gui")]
pub mod icon;
#[cfg(feature = "wasm")]
pub mod wasm;

/// Build-time root attestation (populated by build.rs).
/// If fm_root.key is present at build time, contains ROOT_PUBKEY + BUILD_TOKEN.
/// Otherwise both are None (unauthorized / dev build).
pub mod build_info {
    include!(concat!(env!("OUT_DIR"), "/generated_build_token.rs"));
}

pub const FORMAT_VERSION: u8 = 2;
pub const AUTHOR: &str = "Maksym Skorina";
pub const VERSION: &str = "3.16.5";
pub const PRODUCT_NAME: &str = "FM Aero Code 2";

/// Hard cap on decompressed payload size (512 MiB).
pub const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

/// Hard cap on compressed payload size (256 MiB).
pub const MAX_COMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// AeroGlint spectral grid side (encoder and decoder must match).
pub const AEROGLINT_GRID: usize = 128;