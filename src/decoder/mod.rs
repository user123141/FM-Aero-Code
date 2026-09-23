pub mod aeroglint;
pub mod apng_reader;
pub mod pipeline;

pub use pipeline::{decode_from_bytes, decode_image, peek_header_from_bytes, DecodeOutcome};