//! Audio steganography (MDCT-QIM + BitPerfect LSB).
//!
//! Reuses FEC, AeroSeal, Ed25519, and FMSA stream format.
//!
//! Two modes:
//!   Robust      - MDCT-domain QIM, survives MP3 320 / AAC 256
//!   BitPerfect  - LSB of PCM samples, lossless formats only (WAV/FLAC)
//!
//! CLI: `fm_audio embed|extract|capacity`

pub mod wav;
pub mod mdct;
pub mod mask;
pub mod embed;

pub use wav::{read_wav, write_wav, WavFile};
pub use embed::{
    embed_wav, extract_wav, capacity_bytes,
    AudioMode, AudioEmbedOptions, AudioEmbedOutcome, AudioExtract,
    FMSA_MAGIC, BITS_PER_FRAME, QIM_STEP,
};

/// Stream magic re-export.
pub const AUDIO_STREAM_MAGIC: [u8; 4] = FMSA_MAGIC;