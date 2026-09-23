//! DCT-based steganography for FM Aero Code 2.
//!
//! Embeds data into the AC coefficients of an 8x8 block DCT of the luma
//! channel. Uses QIM (Quantization Index Modulation): each coefficient
//! carries 1 bit, extracted by reading the parity of its quantized value.
//!
//! Visual impact is minimal because we only touch high-frequency
//! coefficients (linear index >= 10 in zig-zag order), which the human
//! eye is insensitive to. The carrier photo looks unchanged.
//!
//! Data flow:
//!   carrier.png + payload.bin -> stego.png (looks like carrier)
//!   stego.png -> payload.bin (extracts and verifies)

pub mod dct;
pub mod embed;

pub use embed::{embed, extract, capacity_bytes, capacity_bytes_for, StegoMode, StegoOptions, StegoOutcome, StegoExtract};

/// Magic prefix for the stego payload stream (after FEC + optional seal).
pub const STEGO_MAGIC: [u8; 4] = *b"FMS2";