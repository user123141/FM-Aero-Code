//! DCT steganography: embed and extract arbitrary bytes from a carrier image.

use anyhow::{anyhow, Result};
use image::{DynamicImage, GrayImage, Luma, Rgb, RgbImage};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::dct::{dct8x8, idct8x8, BLOCK_AREA, EMBED_IDX};
use crate::steganography::STEGO_MAGIC;

/// QIM quantization step. Larger = more robust but more visible.
/// 14 is a good balance for natural images: max per-pixel change ~ +-2.
pub const QIM_DELTA: f32 = 10.0;

/// Minimum side length in blocks. 64x64 px = 8x8 blocks = 64 blocks.
const MIN_SIDE: u32 = 64;

#[derive(Debug, Clone)]
pub struct StegoOptions {
    /// Optional password for AeroSeal encryption.
    pub password: String,
    /// Optional original filename to store inside the header.
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

/// How many payload bytes can a WxH RGB image hold?
pub fn capacity_bytes(w: u32, h: u32) -> usize {
    let bx = w / 8;
    let by = h / 8;
    let blocks = (bx as usize) * (by as usize);
    let bits = blocks * EMBED_IDX.len();
    let raw = bits / 8;
    // 16 bytes header + FEC overhead (255/223) + safety margin
    let after_header = raw.saturating_sub(16);
    // FEC takes ~ 255/223 = 1.143x overhead
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

fn rgb_to_ycbcr(img: &RgbImage) -> (Vec<f32>, Vec<f32>, Vec<f32>, u32, u32) {
    let (w, h) = (img.width(), img.height());
    let n = (w * h) as usize;
    let mut y = vec![0.0f32; n];
    let mut cb = vec![0.0f32; n];
    let mut cr = vec![0.0f32; n];
    for (i, p) in img.pixels().enumerate() {
        let r = p.0[0] as f32;
        let g = p.0[1] as f32;
        let b = p.0[2] as f32;
        y[i] = 0.299 * r + 0.587 * g + 0.114 * b;
        cb[i] = -0.168736 * r - 0.331264 * g + 0.5 * b + 128.0;
        cr[i] = 0.5 * r - 0.418688 * g - 0.081312 * b + 128.0;
    }
    (y, cb, cr, w, h)
}

fn ycbcr_to_rgb(y: &[f32], cb: &[f32], cr: &[f32], w: u32, h: u32) -> RgbImage {
    let mut out = RgbImage::new(w, h);
    for yy in 0..h {
        for xx in 0..w {
            let i = (yy * w + xx) as usize;
            let yv = y[i];
            let cbv = cb[i] - 128.0;
            let crv = cr[i] - 128.0;
            let r = yv + 1.402 * crv;
            let g = yv - 0.344136 * cbv - 0.714136 * crv;
            let b = yv + 1.772 * cbv;
            out.put_pixel(xx, yy, Rgb([
                r.round().clamp(0.0, 255.0) as u8,
                g.round().clamp(0.0, 255.0) as u8,
                b.round().clamp(0.0, 255.0) as u8,
            ]));
        }
    }
    out
}

/// Build the bitstream to embed: [magic 4][len 4][flags 1][hash 8][stream N]
/// Payload is optionally encrypted (seal) and always FEC-wrapped.
fn build_stream(payload: &[u8], opts: &StegoOptions) -> Result<(Vec<u8>, CipherKind)> {
    // 1. Optional encryption
    let (enc_bytes, cipher) = if opts.password.is_empty() {
        (payload.to_vec(), CipherKind::None)
    } else {
        let sealed = crate::crypto::seal::seal(
            &opts.password, payload, crate::crypto::SealMode::Padded,
        )?;
        (sealed, CipherKind::SealV1)
    };

    // 2. FEC wrap
    let fec_data = fec::encode(&enc_bytes)?;

    // 3. Header: magic + fec_len + flags + hash
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

/// Embed payload into carrier, return stego image (RGB).
pub fn embed(carrier: &DynamicImage, payload: &[u8], opts: &StegoOptions) -> Result<StegoOutcome> {
    let rgb = carrier.to_rgb8();
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

    // Bits (MSB first per byte)
    let mut bits: Vec<u8> = Vec::with_capacity(stream.len() * 8);
    for &b in &stream {
        for k in (0..8).rev() {
            bits.push((b >> k) & 1);
        }
    }

    // Convert to YCbCr
    let (mut y, cb, cr, _w, _h) = rgb_to_ycbcr(&rgb);

    // Process 8x8 blocks
    let bx = (w / 8) as usize;
    let by = (h / 8) as usize;
    let mut bit_i = 0usize;

    'outer: for byi in 0..by {
        for bxi in 0..bx {
            let x0 = bxi * 8;
            let y0 = byi * 8;
            // Load block into f32
            let mut block = [0.0f32; BLOCK_AREA];
            for yy in 0..8 {
                for xx in 0..8 {
                    block[yy * 8 + xx] = y[(y0 + yy) * w as usize + (x0 + xx)];
                }
            }
            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);

            // Snapshot how many bits go into this block
            let block_bit_start = bit_i;
            for &idx in EMBED_IDX.iter() {
                if bit_i >= bits.len() { break; }
                dct[idx] = qim_embed(dct[idx], bits[bit_i]);
                bit_i += 1;
            }
            let block_bits_end = bit_i;

            // Iterative refinement: IDCT -> clamp -> re-DCT -> verify -> adjust
            let mut spatial = [0.0f32; BLOCK_AREA];
            let mut current_dct = dct;
            for _pass in 0..3 {
                idct8x8(&current_dct, &mut spatial);
                for v in spatial.iter_mut() { *v = v.clamp(0.0, 255.0); }
                let mut verify = [0.0f32; BLOCK_AREA];
                dct8x8(&spatial, &mut verify);
                let mut all_ok = true;
                for (k, &idx) in EMBED_IDX.iter().enumerate() {
                    let bi = block_bit_start + k;
                    if bi >= block_bits_end { break; }
                    let want = bits[bi];
                    let got = qim_extract(verify[idx]);
                    if want != got {
                        all_ok = false;
                        let q = (verify[idx] / QIM_DELTA).round() as i32;
                        let q_adj = if want == 1 {
                            if q % 2 == 0 { q + 1 } else { q }
                        } else {
                            if q % 2 == 1 { q + 1 } else { q }
                        };
                        current_dct[idx] = (q_adj as f32) * QIM_DELTA;
                    }
                }
                if all_ok { break; }
            }

            for yy in 0..8 {
                for xx in 0..8 {
                    y[(y0 + yy) * w as usize + (x0 + xx)] = spatial[yy * 8 + xx];
                }
            }
            if bit_i >= bits.len() { break 'outer; }
        }
    }

    if bit_i < bits.len() {
        return Err(anyhow!("carrier ran out of capacity: wrote {} of {} bits", bit_i, bits.len()));
    }

    let out = ycbcr_to_rgb(&y, &cb, &cr, w, h);
    Ok(StegoOutcome {
        image: out,
        payload_bytes: payload.len(),
        fec_bytes: stream.len(),
        capacity_bytes: cap,
        cipher,
        content_hash: hex::encode(content_hash_8(payload)),
    })
}

/// Extract payload from stego image.
pub fn extract(stego: &DynamicImage, password: &str) -> Result<Vec<u8>> {
    let rgb = stego.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("image too small"));
    }
    let (y, _cb, _cr, _w, _h) = rgb_to_ycbcr(&rgb);
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
                    block[yy * 8 + xx] = y[(y0 + yy) * w as usize + (x0 + xx)];
                }
            }
            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);
            for &idx in EMBED_IDX.iter() {
                bits.push(qim_extract(dct[idx]));
            }
        }
    }

    // Pack bits into bytes (MSB first)
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
        if password.is_empty() {
            return Err(anyhow!("password required for extraction"));
        }
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

// Keep `GrayImage` / `Luma` imports used (for compatibility in future).
#[allow(dead_code)]
fn _keep_imports(g: &GrayImage) -> Luma<u8> {
    *g.get_pixel(0, 0)
}