//! DCT steganography v3.7.2 - fixed round-trip with final IDCT.

use anyhow::{anyhow, Result};
use image::{DynamicImage, RgbImage};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::dct::{dct8x8, idct8x8, BLOCK_AREA, EMBED_IDX};
use crate::steganography::STEGO_MAGIC;

pub const QIM_DELTA: f32 = 16.0;
const MIN_SIDE: u32 = 64;
const REFINE_PASSES: usize = 6;

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
    let after_header = raw.saturating_sub(17);
    (after_header * 223) / 255
}

fn qim_place(c: f32, bit: u8) -> f32 {
    let q = (c / QIM_DELTA).round() as i32;
    let target = bit as i32;
    let parity = ((q % 2) + 2) % 2;
    if parity == target {
        q as f32 * QIM_DELTA
    } else {
        let down = q - 1;
        let up = q + 1;
        let d_down = (c - down as f32 * QIM_DELTA).abs();
        let d_up = (c - up as f32 * QIM_DELTA).abs();
        let q2 = if d_down < d_up { down } else { up };
        q2 as f32 * QIM_DELTA
    }
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
            if bit_i >= bits.len() { break 'outer; }
            let x0 = (bxi * 8) as u32;
            let y0 = (byi * 8) as u32;

            let mut block = [0.0f32; BLOCK_AREA];
            for yy in 0..8 {
                for xx in 0..8 {
                    let px = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32);
                    block[yy * 8 + xx] = px.0[0] as f32;
                }
            }

            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);

            let bit_start = bit_i;
            for &idx in EMBED_IDX.iter() {
                if bit_i >= bits.len() { break; }
                dct[idx] = qim_place(dct[idx], bits[bit_i]);
                bit_i += 1;
            }
            let bit_end = bit_i;

            // Refinement: converge dct so that IDCT-round-DCT preserves bit parities
            for _pass in 0..REFINE_PASSES {
                let mut sp = [0.0f32; BLOCK_AREA];
                idct8x8(&dct, &mut sp);
                let mut sp_i = [0u8; BLOCK_AREA];
                for i in 0..BLOCK_AREA {
                    sp_i[i] = sp[i].round().clamp(0.0, 255.0) as u8;
                }
                let mut sp_f = [0.0f32; BLOCK_AREA];
                for i in 0..BLOCK_AREA { sp_f[i] = sp_i[i] as f32; }
                let mut verify = [0.0f32; BLOCK_AREA];
                dct8x8(&sp_f, &mut verify);

                let mut all_ok = true;
                for (k, &idx) in EMBED_IDX.iter().enumerate() {
                    let bi = bit_start + k;
                    if bi >= bit_end { break; }
                    if qim_extract(verify[idx]) != bits[bi] {
                        all_ok = false;
                        let diff = verify[idx] - dct[idx];
                        let target = qim_place(verify[idx], bits[bi]);
                        dct[idx] = target - diff;
                    }
                }
                if all_ok { break; }
            }

            // FINAL: always IDCT from the FINAL dct (after the last correction)
            let mut final_sp = [0.0f32; BLOCK_AREA];
            idct8x8(&dct, &mut final_sp);
            for yy in 0..8 {
                for xx in 0..8 {
                    let v = final_sp[yy * 8 + xx].round().clamp(0.0, 255.0) as u8;
                    let px = rgb.get_pixel_mut(x0 + xx as u32, y0 + yy as u32);
                    px.0[0] = v;
                }
            }
        }
    }

    if bit_i < bits.len() {
        return Err(anyhow!("carrier ran out: wrote {} of {} bits", bit_i, bits.len()));
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
    let mut bits: Vec<u8> = Vec::with_capacity(bx * by * EMBED_IDX.len());

    for byi in 0..by {
        for bxi in 0..bx {
            let x0 = (bxi * 8) as u32;
            let y0 = (byi * 8) as u32;
            let mut block = [0.0f32; BLOCK_AREA];
            for yy in 0..8 {
                for xx in 0..8 {
                    let px = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32);
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

    if raw.len() < 17 {
        return Err(anyhow!("stego header truncated ({} bytes)", raw.len()));
    }
    if raw[0..4] != STEGO_MAGIC {
        let got: String = raw[0..4].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("no FMS1 magic (got bytes: {})", got));
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
        if password.is_empty() { return Err(anyhow!("password required")); }
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