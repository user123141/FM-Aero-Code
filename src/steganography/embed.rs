//! Steganography v3.8.4: two modes.
//!
//! BitPerfect (pixel-LSB):
//!   p_new = (p & 0xFE) | bit. Change <=1 per channel, bit-perfect
//!   through PNG save/reload. Does NOT survive JPEG.
//!   Capacity ~ W*H*3/8 bytes.
//!
//! Robust (DCT-QIM):
//!   Quantize 10 mid-freq DCT coefficients per 8x8 block.
//!   Delta=18 (aggressive, survives JPEG q>=85).
//!   Capacity ~ W*H/8 * 10 / 8 / 1.143 bytes.
//!
//! extract() auto-detects: tries LSB first, then DCT-QIM.

use anyhow::{anyhow, Result};
use image::{DynamicImage, RgbImage};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::dct::{dct8x8, idct8x8, BLOCK_AREA, EMBED_IDX};
use crate::steganography::STEGO_MAGIC;

const MIN_SIDE: u32 = 64;
const ROBUST_DELTA: f32 = 18.0;
const ROBUST_REFINE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoMode {
    /// Pixel-LSB. 100% reliable through PNG. Not JPEG-resistant.
    BitPerfect,
    /// DCT-QIM. Survives JPEG q>=85. Bigger visual footprint.
    Robust,
}

impl Default for StegoMode {
    fn default() -> Self { Self::BitPerfect }
}

impl StegoMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BitPerfect => "BitPerfect (PNG)",
            Self::Robust => "Robust (JPEG)",
        }
    }
    pub fn short(&self) -> &'static str {
        match self {
            Self::BitPerfect => "BitPerfect",
            Self::Robust => "Robust",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StegoOptions {
    pub password: String,
    pub original_name: String,
    pub mode: StegoMode,
}

impl Default for StegoOptions {
    fn default() -> Self {
        Self { password: String::new(), original_name: String::new(), mode: StegoMode::BitPerfect }
    }
}

#[derive(Debug, Clone)]
pub struct StegoExtract {
    pub payload: Vec<u8>,
    pub name: String,
    pub cipher: CipherKind,
    pub content_hash: String,
}

#[derive(Debug, Clone)]
pub struct StegoOutcome {
    pub image: RgbImage,
    pub payload_bytes: usize,
    pub fec_bytes: usize,
    pub capacity_bytes: usize,
    pub cipher: CipherKind,
    pub content_hash: String,
    pub mode: StegoMode,
}

// ============================================================
// Capacity (depends on mode)
// ============================================================
pub fn capacity_bytes(w: u32, h: u32) -> usize {
    capacity_bytes_for(w, h, StegoMode::BitPerfect)
}

pub fn capacity_bytes_for(w: u32, h: u32, mode: StegoMode) -> usize {
    match mode {
        StegoMode::BitPerfect => {
            let bits = (w as usize) * (h as usize) * 3;
            let raw = bits / 8;
            let after = raw.saturating_sub(18 + 200);
            (after * 223) / 255
        }
        StegoMode::Robust => {
            let blocks = (w as usize / 8) * (h as usize / 8);
            let bits = blocks * EMBED_IDX.len();
            let raw = bits / 8;
            let after = raw.saturating_sub(18 + 200);
            (after * 223) / 255
        }
    }
}

// ============================================================
// Common stream builder
// ============================================================
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

    // FMS2 layout:
    //   [magic 4] [fec_len u32] [flags u8] [hash 8] [name_len u8] [name 0..200] [fec_data]
    let name_bytes = opts.original_name.as_bytes();
    let name_len = name_bytes.len().min(200);

    let mut out = Vec::with_capacity(18 + name_len + fec_data.len());
    out.extend_from_slice(&STEGO_MAGIC);
    out.extend_from_slice(&(fec_data.len() as u32).to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&hash);
    out.push(name_len as u8);
    out.extend_from_slice(&name_bytes[..name_len]);
    out.extend_from_slice(&fec_data);
    Ok((out, cipher))
}

fn unpack_bits(stream: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(stream.len() * 8);
    for &b in stream {
        for k in (0..8).rev() {
            bits.push((b >> k) & 1);
        }
    }
    bits
}

fn pack_bytes(bits: &[u8]) -> Vec<u8> {
    let n = bits.len() / 8;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = 0u8;
        for k in 0..8 {
            b |= bits[i * 8 + k] << (7 - k);
        }
        out.push(b);
    }
    out
}

// ============================================================
// BitPerfect (pixel-LSB)
// ============================================================
fn embed_bit_perfect(mut rgb: RgbImage, stream: &[u8]) -> Result<RgbImage> {
    let bits = unpack_bits(stream);
    let (w, h) = (rgb.width(), rgb.height());
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
    if bit_i < bits.len() {
        return Err(anyhow!("LSB: wrote {} of {} bits", bit_i, bits.len()));
    }
    Ok(rgb)
}

fn extract_bit_perfect(rgb: &RgbImage) -> Vec<u8> {
    let (w, h) = (rgb.width(), rgb.height());
    let mut bits = Vec::with_capacity((w as usize) * (h as usize) * 3);
    for y in 0..h {
        for x in 0..w {
            let px = rgb.get_pixel(x, y);
            for ch in 0..3 {
                bits.push(px.0[ch] & 1);
            }
        }
    }
    pack_bytes(&bits)
}

// ============================================================
// Robust (DCT-QIM)
// ============================================================
fn qim_place(c: f32, bit: u8, delta: f32) -> f32 {
    let q = (c / delta).round() as i32;
    let target = bit as i32;
    let parity = ((q % 2) + 2) % 2;
    if parity == target {
        q as f32 * delta
    } else {
        let down = q - 1;
        let up = q + 1;
        let d_down = (c - down as f32 * delta).abs();
        let d_up = (c - up as f32 * delta).abs();
        let q2 = if d_down < d_up { down } else { up };
        q2 as f32 * delta
    }
}

fn qim_read(c: f32, delta: f32) -> u8 {
    let q = (c / delta).round() as i32;
    (((q % 2) + 2) % 2) as u8
}

fn embed_robust(mut rgb: RgbImage, stream: &[u8]) -> Result<RgbImage> {
    let bits = unpack_bits(stream);
    let (w, h) = (rgb.width(), rgb.height());
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
                    block[yy * 8 + xx] = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32).0[0] as f32;
                }
            }
            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);

            let bit_start = bit_i;
            for &idx in EMBED_IDX.iter() {
                if bit_i >= bits.len() { break; }
                dct[idx] = qim_place(dct[idx], bits[bit_i], ROBUST_DELTA);
                bit_i += 1;
            }
            let bit_end = bit_i;

            // Refinement to survive rounding
            for _pass in 0..ROBUST_REFINE {
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
                    if qim_read(verify[idx], ROBUST_DELTA) != bits[bi] {
                        all_ok = false;
                        let diff = verify[idx] - dct[idx];
                        let target = qim_place(verify[idx], bits[bi], ROBUST_DELTA);
                        dct[idx] = target - diff;
                    }
                }
                if all_ok { break; }
            }

            // Final IDCT from current dct
            let mut sp = [0.0f32; BLOCK_AREA];
            idct8x8(&dct, &mut sp);
            for yy in 0..8 {
                for xx in 0..8 {
                    let v = sp[yy * 8 + xx].round().clamp(0.0, 255.0) as u8;
                    rgb.get_pixel_mut(x0 + xx as u32, y0 + yy as u32).0[0] = v;
                }
            }
        }
    }

    if bit_i < bits.len() {
        return Err(anyhow!("Robust: wrote {} of {} bits", bit_i, bits.len()));
    }
    Ok(rgb)
}

fn extract_robust(rgb: &RgbImage) -> Vec<u8> {
    let (w, h) = (rgb.width(), rgb.height());
    let bx = (w / 8) as usize;
    let by = (h / 8) as usize;
    let mut bits = Vec::with_capacity(bx * by * EMBED_IDX.len());
    for byi in 0..by {
        for bxi in 0..bx {
            let x0 = (bxi * 8) as u32;
            let y0 = (byi * 8) as u32;
            let mut block = [0.0f32; BLOCK_AREA];
            for yy in 0..8 {
                for xx in 0..8 {
                    block[yy * 8 + xx] = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32).0[0] as f32;
                }
            }
            let mut dct = [0.0f32; BLOCK_AREA];
            dct8x8(&block, &mut dct);
            for &idx in EMBED_IDX.iter() {
                bits.push(qim_read(dct[idx], ROBUST_DELTA));
            }
        }
    }
    pack_bytes(&bits)
}

// ============================================================
// Public API
// ============================================================
pub fn embed(carrier: &DynamicImage, payload: &[u8], opts: &StegoOptions) -> Result<StegoOutcome> {
    let rgb = carrier.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("carrier too small (min {}x{})", MIN_SIDE, MIN_SIDE));
    }
    let cap = capacity_bytes_for(w, h, opts.mode);
    if payload.len() > cap {
        return Err(anyhow!("payload {} B > capacity {} B ({})", payload.len(), cap, opts.mode.short()));
    }

    let (stream, cipher) = build_stream(payload, opts)?;
    if stream.len() > cap {
        return Err(anyhow!("stream {} B > capacity {} B ({})", stream.len(), cap, opts.mode.short()));
    }

    let out_image = match opts.mode {
        StegoMode::BitPerfect => embed_bit_perfect(rgb, &stream)?,
        StegoMode::Robust => embed_robust(rgb, &stream)?,
    };

    Ok(StegoOutcome {
        image: out_image,
        payload_bytes: payload.len(),
        fec_bytes: stream.len(),
        capacity_bytes: cap,
        cipher,
        content_hash: hex::encode(content_hash_8(payload)),
        mode: opts.mode,
    })
}

fn try_decode_stream(raw: &[u8], password: &str) -> Result<StegoExtract> {
    if raw.len() < 18 {
        return Err(anyhow!("stego header truncated ({} bytes)", raw.len()));
    }
    if raw[0..4] != STEGO_MAGIC {
        let got: String = raw[0..4].iter()
            .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("no FMS2 magic (got: {})", got));
    }
    let fec_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let flags = raw[8];
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&raw[9..17]);
    let name_len = raw[17] as usize;
    if 18 + name_len > raw.len() {
        return Err(anyhow!("name overflow: 18+{} > {}", name_len, raw.len()));
    }
    let name = if name_len > 0 {
        String::from_utf8_lossy(&raw[18..18 + name_len]).to_string()
    } else {
        String::new()
    };
    let fec_start = 18 + name_len;
    if fec_start + fec_len > raw.len() {
        return Err(anyhow!("stream truncated: need {}, have {}", fec_start + fec_len, raw.len()));
    }
    let fec_bytes = &raw[fec_start..fec_start + fec_len];
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
    let cipher = if flags & 1 != 0 { CipherKind::SealV1 } else { CipherKind::None };
    Ok(StegoExtract {
        payload,
        name,
        cipher,
        content_hash: hex::encode(hash),
    })
}

/// Auto-detecting extract: tries LSB first, then DCT-QIM.
pub fn extract(stego: &DynamicImage, password: &str) -> Result<StegoExtract> {
    let rgb = stego.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("image too small"));
    }

    let lsb_raw = extract_bit_perfect(&rgb);
    if let Ok(p) = try_decode_stream(&lsb_raw, password) {
        return Ok(p);
    }

    let robust_raw = extract_robust(&rgb);
    match try_decode_stream(&robust_raw, password) {
        Ok(p) => Ok(p),
        Err(e_robust) => Err(anyhow!(
            "auto-detect failed: LSB no match; Robust: {}", e_robust)),
    }
}