//! DCT steganography: embed and extract arbitrary bytes from a carrier image.
//!
//! v3.7.1: embed directly in the R channel (no YCbCr roundtrip).
//! Rationale: RGB->YCbCr->RGB->YCbCr introduces +-1 drift in Y, which
//! flips QIM bits near bin boundaries. R-channel is lossless through
//! PNG save/reload, so we sidestep the entire class of bugs.

use anyhow::{anyhow, Result};
use image::{DynamicImage, RgbImage};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::dct::{dct8x8, idct8x8, BLOCK_AREA, EMBED_IDX};
use crate::steganography::STEGO_MAGIC;

/// QIM quantization step. Larger = more robust but more visible.
pub const QIM_DELTA: f32 = 14.0;

const MIN_SIDE: u32 = 64;

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

pub fn capacity_bytes(w: u32, h: u32) -> usize {
    let bx = w / 8;
    let by = h / 8;
    let blocks = (bx as usize) * (by as usize);
    let bits = blocks * EMBED_IDX.len();
    let raw = bits / 8;
    let after_header = raw.saturating_sub(16);
    let payload = (after_header * 223) / 255;
    payload
}

fn qim_embed(c: f32, bit: u8) -> f32 {
    let q = (c / QIM_DELTA).round() as i32;
    let target = bit as i32;
    let parity = ((q % 2) + 2) % 2;
    if parity == target {
        return q as f32 * QIM_DELTA;
    }
    let down = q - 1;
    let up = q + 1;
    let d_down = (c - (down as f32 * QIM_DELTA)).abs();
    let d_up = (c - (up as f32 * QIM_DELTA)).abs();
    let q2 = if d_down < d_up { down } else { up };
    q2 as f32 * QIM_DELTA
}

fn qim_extract(c: f32) -> u8 {
    let q = (c / QIM_DELTA).round() as i32;
    (((q % 2) + 2) % 2) as u8
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
    let flags: u8 = match cipher {
        CipherKind::None => 0,
        _ => 1,
    };
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

    let mut bits: Vec<u8> = Vec::with_capacity(stream.len() * 8);
    for &b in &stream {
        for k in (0..8).rev() {
            bits.push((b >> k) & 1);
        }
    }

    let bx = (w / 8) as usize;
    let by = (h / 8) as usize;
    let mut bit_i = 0usize;

    'outer: for byi in 0..by {
        for bxi in 0..bx {
            let x0 = bxi * 8;
            let y0 = byi * 8;

            let mut block = [0.0f32; BLOCK_AREA];
            for yy in 0..8 {
                for xx in 0..8 {
                    let px = rgb.get_pixel((x0 + xx) as u32, (y0 + yy) as u32);
                    block[yy * 8 + xx] = px.0[0] as f32;
                }
            }
            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);

            let bit_start = bit_i;
            for &idx in EMBED_IDX.iter() {
                if bit_i >= bits.len() { break; }
                dct[idx] = qim_embed(dct[idx], bits[bit_i]);
                bit_i += 1;
            }
            let bit_end = bit_i;

            // Iterative refinement with integer rounding (matches actual save)
            let mut spatial_int = [0u8; BLOCK_AREA];
            for _pass in 0..8 {
                let mut spatial = [0.0f32; BLOCK_AREA];
                idct8x8(&dct, &mut spatial);
                for i in 0..BLOCK_AREA {
                    spatial_int[i] = spatial[i].round().clamp(0.0, 255.0) as u8;
                }
                let mut spatial_f = [0.0f32; BLOCK_AREA];
                for i in 0..BLOCK_AREA { spatial_f[i] = spatial_int[i] as f32; }
                let mut verify = [0.0f32; BLOCK_AREA];
                dct8x8(&spatial_f, &mut verify);

                let mut all_ok = true;
                for (k, &idx) in EMBED_IDX.iter().enumerate() {
                    let bi = bit_start + k;
                    if bi >= bit_end { break; }
                    let want = bits[bi];
                    let got = qim_extract(verify[idx]);
                    if want != got {
                        all_ok = false;
                        let q_now = (verify[idx] / QIM_DELTA).round() as i32;
                        let target_parity = want as i32;
                        let q_adj = if ((q_now % 2) + 2) % 2 == target_parity {
                            q_now
                        } else {
                            let up = q_now + 1;
                            let down = q_now - 1;
                            let d_up = (verify[idx] - (up as f32) * QIM_DELTA).abs();
                            let d_down = (verify[idx] - (down as f32) * QIM_DELTA).abs();
                            if d_down < d_up { down } else { up }
                        };
                        dct[idx] = q_adj as f32 * QIM_DELTA;
                    }
                }
                if all_ok { break; }
            }

            for yy in 0..8 {
                for xx in 0..8 {
                    let px = rgb.get_pixel_mut((x0 + xx) as u32, (y0 + yy) as u32);
                    px.0[0] = spatial_int[yy * 8 + xx];
                }
            }

            if bit_i >= bits.len() { break 'outer; }
        }
    }

    if bit_i < bits.len() {
        return Err(anyhow!("carrier ran out of capacity: wrote {} of {} bits", bit_i, bits.len()));
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
    let bx = (w / 8) as usize;
    let by = (h / 8) as usize;
    let max_bits = bx * by * EMBED_IDX.len();
    let mut bits: Vec<u8> = Vec::with_capacity(max_bits);

    for byi in 0..by {
        for bxi in 0..bx {
            let x0 = bxi * 8;
            let y0 = byi * 8;
            let mut block = [0.0f32; BLOCK_AREA];
            for yy in 0..8 {
                for xx in 0..8 {
                    let px = rgb.get_pixel((x0 + xx) as u32, (y0 + yy) as u32);
                    block[yy * 8 + xx] = px.0[0] as f32;
                }
            }
            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);
            for &idx in EMBED_IDX.iter() {
                bits.push(qim_extract(dct[idx]));
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

    if raw.len() < 17 { return Err(anyhow!("stego header truncated")); }
    if raw[0..4] != STEGO_MAGIC { return Err(anyhow!("no FMS1 magic")); }
    let fec_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let flags = raw[8];
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&raw[9..17]);

    if 17 + fec_len > raw.len() {
        return Err(anyhow!("stego stream truncated: need {}, have {}", 17 + fec_len, raw.len()));
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