#![allow(dead_code)]
#![forbid(unsafe_code)]

//! FM Aero Code 2 - Fast Memory optical storage.
//!
//! Encodes any file into a printable black-and-white pattern.
//! Uses FFT-based OFDM transport (AeroGlint Spectrum Protocol).

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

#[cfg(feature = "gui")]
pub mod app;
#[cfg(feature = "gui")]
pub mod icon;
#[cfg(feature = "wasm")]
pub mod wasm;

pub const FORMAT_VERSION: u8 = 2;
pub const AUTHOR: &str = "Maksym Skorina";
pub const VERSION: &str = "3.7.2";
pub const PRODUCT_NAME: &str = "FM Aero Code 2";

/// Hard cap on decompressed payload size (512 MiB).
pub const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

/// Hard cap on compressed payload size (256 MiB).
pub const MAX_COMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// AeroGlint spectral grid side (encoder and decoder must match).
pub const AEROGLINT_GRID: usize = 128;