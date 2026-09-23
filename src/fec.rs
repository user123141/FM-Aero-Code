//! Reed-Solomon FEC over QPSK payloads (v2.2.0).
//!
//! Uses reed-solomon = "0.2" API:
//!   - Encoder::new(ecc_len).encode(&data) -> Buffer
//!   - Decoder::new(ecc_len).correct(&mut corrupted, Some(&erasures)) -> Result<Buffer, _>
//!   - Buffer::data() -> &[u8], Buffer::ecc() -> &[u8]
//!
//! Wire format: [orig_len: u32 LE][rs_block_0][rs_block_1]...
//! Each rs_block is 255 bytes (223 data + 32 parity).

use anyhow::{anyhow, Result};
use reed_solomon::{Decoder, Encoder};

pub const ECC_BYTES: usize = 32;
pub const DATA_BYTES: usize = 255 - ECC_BYTES;
pub const BLOCK_BYTES: usize = 255;

const MAX_OUTPUT: usize = 512 * 1024 * 1024;

pub fn encode(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > MAX_OUTPUT {
        return Err(anyhow!("fec: input {} > cap {}", data.len(), MAX_OUTPUT));
    }
    let enc = Encoder::new(ECC_BYTES);
    let block_count = ((data.len() + DATA_BYTES - 1) / DATA_BYTES).max(1);
    let mut out = Vec::with_capacity(4 + block_count * BLOCK_BYTES);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());

    if data.is_empty() {
        let encoded = enc.encode(&[0u8; DATA_BYTES]);
        out.extend_from_slice(encoded.data());
        out.extend_from_slice(encoded.ecc());
        return Ok(out);
    }

    for chunk in data.chunks(DATA_BYTES) {
        let mut buf = [0u8; DATA_BYTES];
        buf[..chunk.len()].copy_from_slice(chunk);
        let encoded = enc.encode(&buf);
        out.extend_from_slice(encoded.data());
        out.extend_from_slice(encoded.ecc());
    }
    Ok(out)
}

pub fn decode(encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.len() < 4 {
        return Err(anyhow!("fec: too short"));
    }
    let original_len = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
    if original_len > MAX_OUTPUT {
        return Err(anyhow!("fec: declared {} > cap {}", original_len, MAX_OUTPUT));
    }

    let dec = Decoder::new(ECC_BYTES);
    let body = &encoded[4..];
    let mut out: Vec<u8> = Vec::with_capacity(original_len);

    let mut pos = 0usize;
    while pos + BLOCK_BYTES <= body.len() && out.len() < original_len {
        let mut block = [0u8; BLOCK_BYTES];
        block.copy_from_slice(&body[pos..pos + BLOCK_BYTES]);
        let corrected = match dec.correct(&mut block, None) {
            Ok(c) => c,
            Err(e) => {
                let nonzero = block.iter().filter(|&&b| b != 0).count();
                let mut snap = String::new();
                for b in block.iter().take(8) {
                    snap.push_str(&format!("{:02x} ", b));
                }
                return Err(anyhow!(
                    "fec block {} (bytes {}..{}): {:?} [first8={} nonzero={}/255]",
                    pos / 255, pos, pos + BLOCK_BYTES, e, snap.trim(), nonzero
                ));
            }
        };
        let data = corrected.data();
        let take = (original_len - out.len()).min(data.len());
        out.extend_from_slice(&data[..take]);
        pos += BLOCK_BYTES;
    }

    if out.len() < original_len {
        return Err(anyhow!("fec: incomplete ({} of {})", out.len(), original_len));
    }
    Ok(out)
}