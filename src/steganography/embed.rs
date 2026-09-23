//! Pixel-LSB steganography (v3.8.2).
//!
//! Embeds bits directly into the LSB of R/G/B channels of a carrier photo.
//! Each pixel carries 3 bits (one per channel), change per channel is <=1.
//! Completely invisible to the eye, bit-perfect through PNG save/reload.
//!
//! Rationale: DCT-based LSB on mid-frequency coefficients is fragile -
//! those coefficients are near zero in natural images, and after
//! IDCT->round->DCT the LSB flips randomly. Pixel-domain LSB is stable:
//!   p_new = (p & 0xFE) | bit
//! round-trips through PNG exactly.
//!
//! Capacity: W * H * 3 / 8 bytes (minus header + FEC overhead).
//!   342x584 -> ~74 KB
//!   512x512 -> ~98 KB
//!   1024x1024 -> ~392 KB
//!
//! NOT robust to JPEG (JPEG quantizes LSBs). For JPEG-robust stego,
//! use Robust mode (DCT-QIM, in development).

use anyhow::{anyhow, Result};
use image::{DynamicImage, RgbImage};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::STEGO_MAGIC;

const MIN_SIDE: u32 = 16;

#[derive(Debug, Clone)]
pub struct StegoOptions {
    pub password: String,
    pub original_name: String,
}

impl Default for StegoOptions {
    fn default() -> Self {
        Self { password: String::new(), original_name: String::new() }
    }
}

#[derive(Debug, Clone)]
pub struct StegoOutcome {
    pub image: RgbImage,
    pub payload_bytes: usize,
    pub fec_bytes: usize,
    pub capacity_bytes: usize,
    pub cipher: CipherKind,
    pub content_hash: String,
}

/// Payload capacity in bytes for a WxH carrier image.
pub fn capacity_bytes(w: u32, h: u32) -> usize {
    let total_bits = (w as usize) * (h as usize) * 3;
    let raw = total_bits / 8;
    let after_header = raw.saturating_sub(17);
    (after_header * 223) / 255
}

fn build_stream(payload: &[u8], opts: &StegoOptions) -> Result<(Vec<u8>, CipherKind)> {
    let (enc_bytes, cipher) = if opts.password.is_empty() {
        (payload.to_vec(), CipherKind::None)
    } else {
        let sealed = crate::crypto::seal::seal(
            &opts.password, payload, crate::crypto::SealMode::Padded,
        )?;
        (sealed, CipherKind::SealV1)
    };
    let fec_data = fec::encode(&enc_bytes)?;
    let flags: u8 = match cipher { CipherKind::None => 0, _ => 1 };
    let hash = content_hash_8(payload);
    let mut out = Vec::with_capacity(17 + fec_data.len());
    out.extend_from_slice(&STEGO_MAGIC);
    out.extend_from_slice(&(fec_data.len() as u32).to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&fec_data);
    Ok((out, cipher))
}

pub fn embed(carrier: &DynamicImage, payload: &[u8], opts: &StegoOptions) -> Result<StegoOutcome> {
    let mut rgb = carrier.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("carrier too small (min {}x{})", MIN_SIDE, MIN_SIDE));
    }
    let cap = capacity_bytes(w, h);
    if payload.len() > cap {
        return Err(anyhow!("payload {} B > capacity {} B", payload.len(), cap));
    }

    let (stream, cipher) = build_stream(payload, opts)?;
    if stream.len() > cap {
        return Err(anyhow!("stream {} B > capacity {} B (FEC overhead)", stream.len(), cap));
    }

    // Flatten stream into bits (MSB first per byte)
    let mut bits: Vec<u8> = Vec::with_capacity(stream.len() * 8);
    for &b in &stream {
        for k in (0..8).rev() {
            bits.push((b >> k) & 1);
        }
    }

    let total_channels = (w as usize) * (h as usize) * 3;
    if bits.len() > total_channels {
        return Err(anyhow!("not enough channel capacity"));
    }

    // Write LSBs: iterate pixels row-major, each pixel 3 channels (R,G,B)
    let mut bit_i = 0usize;
    'outer: for y in 0..h {
        for x in 0..w {
            let px = rgb.get_pixel_mut(x, y);
            for ch in 0..3 {
                if bit_i >= bits.len() { break 'outer; }
                px.0[ch] = (px.0[ch] & 0xFE) | bits[bit_i];
                bit_i += 1;
            }
        }
    }

    Ok(StegoOutcome {
        image: rgb,
        payload_bytes: payload.len(),
        fec_bytes: stream.len(),
        capacity_bytes: cap,
        cipher,
        content_hash: hex::encode(content_hash_8(payload)),
    })
}

pub fn extract(stego: &DynamicImage, password: &str) -> Result<Vec<u8>> {
    let rgb = stego.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("image too small"));
    }

    let total_channels = (w as usize) * (h as usize) * 3;
    let mut bits: Vec<u8> = Vec::with_capacity(total_channels);

    for y in 0..h {
        for x in 0..w {
            let px = rgb.get_pixel(x, y);
            for ch in 0..3 {
                bits.push(px.0[ch] & 1);
            }
        }
    }

    let n_bytes = bits.len() / 8;
    let mut raw = Vec::with_capacity(n_bytes);
    for i in 0..n_bytes {
        let mut b = 0u8;
        for k in 0..8 {
            b |= bits[i * 8 + k] << (7 - k);
        }
        raw.push(b);
    }

    if raw.len() < 17 {
        return Err(anyhow!("stego header truncated ({} bytes)", raw.len()));
    }
    if raw[0..4] != STEGO_MAGIC {
        let got: String = raw[0..4].iter()
            .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("no FMS1 magic (got: {})", got));
    }
    let fec_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let flags = raw[8];
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&raw[9..17]);

    if 17 + fec_len > raw.len() {
        return Err(anyhow!("stream truncated: need {}, have {}", 17 + fec_len, raw.len()));
    }
    let fec_bytes = &raw[17..17 + fec_len];
    let enc = fec::decode(fec_bytes).map_err(|e| anyhow!("fec: {}", e))?;

    let payload = if flags & 1 != 0 {
        if password.is_empty() { return Err(anyhow!("password required for extraction")); }
        crate::crypto::seal::open(password, &enc)
            .map_err(|_| anyhow!("wrong password or corrupted"))?
    } else {
        enc
    };

    let expect = content_hash_8(&payload);
    if expect != hash {
        return Err(anyhow!("hash mismatch after extract"));
    }
    Ok(payload)
}