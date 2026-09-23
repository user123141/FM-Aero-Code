#![allow(dead_code)]
#![forbid(unsafe_code)]

pub mod error;
pub mod selftest;
pub mod fec;
pub mod resilience;
pub mod types;
pub mod fastmem;
pub mod crypto;
pub mod encoder;
pub mod decoder;

#[cfg(feature = "gui")]
pub mod app;
#[cfg(feature = "gui")]
pub mod icon;
#[cfg(feature = "wasm")]
pub mod wasm;

pub const FORMAT_VERSION: u8 = 2;
pub const AUTHOR: &str = "Maksym Skorina";
pub const VERSION: &str = "2.7.0";
pub const PRODUCT_NAME: &str = "FM Aero Code 2";

/// Hard cap on decompressed payload size (protection against bombs).
/// 512 MiB. Enforced in decoder pipeline before allocation.
pub const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

/// Hard cap on compressed payload size.
pub const MAX_COMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// AeroGlint spectral grid side (both encoder and decoder must match).
pub const AEROGLINT_GRID: usize = 128;