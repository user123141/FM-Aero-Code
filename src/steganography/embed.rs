//! Steganography v3.9.0.
//!
//! Two modes:
//!   BitPerfect: pixel-LSB on R/G/B. 100% through PNG. Invisible.
//!   Robust: DCT-QIM on 32 low-freq coeffs, RGB, 3x redundant header.
//!           Survives JPEG q>=85 and mild noise.

use anyhow::{anyhow, Result};
use image::{DynamicImage, RgbImage};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::dct::{dct8x8, idct8x8, BLOCK_AREA};
use crate::steganography::STEGO_MAGIC;

const MIN_SIDE: u32 = 64;

// Robust: 32 low-freq zigzag indices (index into y*8+x)
const ROBUST_IDX: [usize; 32] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 18, 11, 25, 32, 4, 33,
    26, 19, 12, 40, 34, 27, 5, 41, 20, 35, 48, 13, 42, 28, 6, 49,
];

const ROBUST_DELTA: f32 = 16.0;
const ROBUST_REFINE: usize = 5;

// Fixed header size: magic(4) + fec_len(4) + flags(1) + hash(8) + name_len(1) + name(200)
const FIXED_HEADER_BYTES: usize = 218;
const FIXED_HEADER_BITS: usize = FIXED_HEADER_BYTES * 8;
const TRIPLED_HEADER_BITS: usize = FIXED_HEADER_BITS * 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoMode { BitPerfect, Robust }

impl Default for StegoMode {
    fn default() -> Self { Self::BitPerfect }
}
impl StegoMode {
    pub fn label(&self) -> &'static str {
        match self { Self::BitPerfect => "BitPerfect (PNG)", Self::Robust => "Robust (JPEG)" }
    }
    pub fn short(&self) -> &'static str {
        match self { Self::BitPerfect => "BitPerfect", Self::Robust => "Robust" }
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
pub struct StegoOutcome {
    pub image: RgbImage,
    pub payload_bytes: usize,
    pub fec_bytes: usize,
    pub capacity_bytes: usize,
    pub cipher: CipherKind,
    pub content_hash: String,
    pub mode: StegoMode,
}

#[derive(Debug, Clone)]
pub struct StegoExtract {
    pub payload: Vec<u8>,
    pub name: String,
    pub cipher: CipherKind,
    pub content_hash: String,
}

// ---------------- Capacity ----------------
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
            let slots = blocks * ROBUST_IDX.len() * 3;
            let payload_slots = slots.saturating_sub(TRIPLED_HEADER_BITS);
            let payload_bytes = payload_slots / 8;
            (payload_bytes * 223) / 255
        }
    }
}

// ---------------- Stream build/parse ----------------
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

fn try_decode_stream(raw: &[u8], password: &str) -> Result<StegoExtract> {
    if raw.len() < 18 {
        return Err(anyhow!("stream too short ({} bytes)", raw.len()));
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
    let name_len = name_len.min(200);
    if 18 + name_len > raw.len() {
        return Err(anyhow!("name overflow"));
    }
    let name = if name_len > 0 {
        String::from_utf8_lossy(&raw[18..18 + name_len]).to_string()
    } else { String::new() };
    let fec_start = 18 + name_len;
    if fec_start + fec_len > raw.len() {
        return Err(anyhow!("stream truncated: need {} + {}, have {}",
            fec_start, fec_len, raw.len()));
    }
    let fec_bytes = &raw[fec_start..fec_start + fec_len];
    let enc = fec::decode(fec_bytes).map_err(|e| anyhow!("fec: {}", e))?;
    let payload = if flags & 1 != 0 {
        if password.is_empty() { return Err(anyhow!("password required")); }
        crate::crypto::seal::open(password, &enc)
            .map_err(|_| anyhow!("wrong password or corrupted"))?
    } else { enc };
    let expect = content_hash_8(&payload);
    if expect != hash {
        return Err(anyhow!("hash mismatch"));
    }
    let cipher = if flags & 1 != 0 { CipherKind::SealV1 } else { CipherKind::None };
    Ok(StegoExtract {
        payload,
        name,
        cipher,
        content_hash: hex::encode(hash),
    })
}

// ---------------- Bit helpers ----------------
fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for k in (0..8).rev() { out.push((b >> k) & 1); }
    }
    out
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let n = bits.len() / 8;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = 0u8;
        for k in 0..8 { b |= bits[i * 8 + k] << (7 - k); }
        out.push(b);
    }
    out
}

fn triple_bits(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len() * 3);
    for &b in bits { out.push(b); out.push(b); out.push(b); }
    out
}

fn untriple_bits(tripled: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tripled.len() / 3);
    for chunk in tripled.chunks(3) {
        if chunk.len() < 3 { break; }
        let s = chunk[0] + chunk[1] + chunk[2];
        out.push(if s >= 2 { 1 } else { 0 });
    }
    out
}

// ---------------- BitPerfect ----------------
fn embed_bit_perfect(mut rgb: RgbImage, stream: &[u8]) -> Result<RgbImage> {
    let bits = bytes_to_bits(stream);
    let (w, h) = (rgb.width(), rgb.height());
    let mut i = 0usize;
    'outer: for y in 0..h {
        for x in 0..w {
            let px = rgb.get_pixel_mut(x, y);
            for ch in 0..3 {
                if i >= bits.len() { break 'outer; }
                px.0[ch] = (px.0[ch] & 0xFE) | bits[i];
                i += 1;
            }
        }
    }
    if i < bits.len() { return Err(anyhow!("LSB overflow")); }
    Ok(rgb)
}

fn extract_bit_perfect(rgb: &RgbImage) -> Vec<u8> {
    let (w, h) = (rgb.width(), rgb.height());
    let mut bits = Vec::with_capacity((w as usize) * (h as usize) * 3);
    for y in 0..h {
        for x in 0..w {
            let px = rgb.get_pixel(x, y);
            for ch in 0..3 { bits.push(px.0[ch] & 1); }
        }
    }
    bits_to_bytes(&bits)
}

// ---------------- Robust ----------------
fn qim_place(c: f32, bit: u8, delta: f32) -> f32 {
    let q = (c / delta).round() as i32;
    let t = bit as i32;
    let p = ((q % 2) + 2) % 2;
    if p == t { q as f32 * delta }
    else {
        let d = q - 1; let u = q + 1;
        let dd = (c - d as f32 * delta).abs();
        let du = (c - u as f32 * delta).abs();
        (if dd < du { d } else { u }) as f32 * delta
    }
}

fn qim_read(c: f32, delta: f32) -> u8 {
    let q = (c / delta).round() as i32;
    (((q % 2) + 2) % 2) as u8
}

fn split_stream(stream: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Returns (fixed_header_218, payload_bytes)
    let mut hdr = vec![0u8; FIXED_HEADER_BYTES];
    let name_len = stream.get(17).copied().unwrap_or(0) as usize;
    let name_len = name_len.min(200);
    let header_len = 18 + name_len;
    if stream.len() >= header_len {
        hdr[..header_len].copy_from_slice(&stream[..header_len]);
    }
    let payload = if stream.len() > header_len {
        stream[header_len..].to_vec()
    } else { Vec::new() };
    (hdr, payload)
}

fn embed_robust(mut rgb: RgbImage, stream: &[u8]) -> Result<RgbImage> {
    let (hdr, payload) = split_stream(stream);
    let tripled = triple_bits(&bytes_to_bits(&hdr));
    let mut all_bits = tripled;
    all_bits.extend_from_slice(&bytes_to_bits(&payload));

    let (w, h) = (rgb.width(), rgb.height());
    let bw = (w / 8) as usize;
    let bh = (h / 8) as usize;
    let mut bit_i = 0usize;

    'outer: for ch in 0..3 {
        for byi in 0..bh {
            for bxi in 0..bw {
                if bit_i >= all_bits.len() { break 'outer; }
                let x0 = (bxi * 8) as u32;
                let y0 = (byi * 8) as u32;

                let mut block = [0.0f32; BLOCK_AREA];
                for yy in 0..8 {
                    for xx in 0..8 {
                        block[yy * 8 + xx] = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32).0[ch] as f32;
                    }
                }
                let mut dct = [0.0f32; BLOCK_AREA];
                dct8x8(&block, &mut dct);

                let bstart = bit_i;
                for &idx in ROBUST_IDX.iter() {
                    if bit_i >= all_bits.len() { break; }
                    dct[idx] = qim_place(dct[idx], all_bits[bit_i], ROBUST_DELTA);
                    bit_i += 1;
                }
                let bend = bit_i;

                for _ in 0..ROBUST_REFINE {
                    let mut sp = [0.0f32; BLOCK_AREA];
                    idct8x8(&dct, &mut sp);
                    let mut spi = [0u8; BLOCK_AREA];
                    for i in 0..BLOCK_AREA {
                        spi[i] = sp[i].round().clamp(0.0, 255.0) as u8;
                    }
                    let mut spf = [0.0f32; BLOCK_AREA];
                    for i in 0..BLOCK_AREA { spf[i] = spi[i] as f32; }
                    let mut verify = [0.0f32; BLOCK_AREA];
                    dct8x8(&spf, &mut verify);
                    let mut ok = true;
                    for (k, &idx) in ROBUST_IDX.iter().enumerate() {
                        let bi = bstart + k;
                        if bi >= bend { break; }
                        if qim_read(verify[idx], ROBUST_DELTA) != all_bits[bi] {
                            ok = false;
                            let diff = verify[idx] - dct[idx];
                            let target = qim_place(verify[idx], all_bits[bi], ROBUST_DELTA);
                            dct[idx] = target - diff;
                        }
                    }
                    if ok { break; }
                }

                let mut sp = [0.0f32; BLOCK_AREA];
                idct8x8(&dct, &mut sp);
                for yy in 0..8 {
                    for xx in 0..8 {
                        let v = sp[yy * 8 + xx].round().clamp(0.0, 255.0) as u8;
                        rgb.get_pixel_mut(x0 + xx as u32, y0 + yy as u32).0[ch] = v;
                    }
                }
            }
        }
    }

    if bit_i < all_bits.len() {
        return Err(anyhow!("Robust: wrote {} of {} bits", bit_i, all_bits.len()));
    }
    Ok(rgb)
}

fn extract_robust_raw(rgb: &RgbImage) -> Vec<u8> {
    let (w, h) = (rgb.width(), rgb.height());
    let bw = (w / 8) as usize;
    let bh = (h / 8) as usize;
    let mut bits: Vec<u8> = Vec::with_capacity(bw * bh * 32 * 3);
    for ch in 0..3 {
        for byi in 0..bh {
            for bxi in 0..bw {
                let x0 = (bxi * 8) as u32;
                let y0 = (byi * 8) as u32;
                let mut block = [0.0f32; BLOCK_AREA];
                for yy in 0..8 {
                    for xx in 0..8 {
                        block[yy * 8 + xx] = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32).0[ch] as f32;
                    }
                }
                let mut dct = [0.0f32; BLOCK_AREA];
                dct8x8(&block, &mut dct);
                for &idx in ROBUST_IDX.iter() {
                    bits.push(qim_read(dct[idx], ROBUST_DELTA));
                }
            }
        }
    }
    bits_to_bytes(&bits)
}

fn extract_robust(rgb: &RgbImage) -> Result<Vec<u8>> {
    let (w, h) = (rgb.width(), rgb.height());
    let bw = (w / 8) as usize;
    let bh = (h / 8) as usize;
    let total_bits = bw * bh * ROBUST_IDX.len() * 3;
    if total_bits < TRIPLED_HEADER_BITS {
        return Err(anyhow!("not enough slots"));
    }

    // Read bits as u8 vec
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for ch in 0..3 {
        for byi in 0..bh {
            for bxi in 0..bw {
                let x0 = (bxi * 8) as u32;
                let y0 = (byi * 8) as u32;
                let mut block = [0.0f32; BLOCK_AREA];
                for yy in 0..8 {
                    for xx in 0..8 {
                        block[yy * 8 + xx] = rgb.get_pixel(x0 + xx as u32, y0 + yy as u32).0[ch] as f32;
                    }
                }
                let mut dct = [0.0f32; BLOCK_AREA];
                dct8x8(&block, &mut dct);
                for &idx in ROBUST_IDX.iter() {
                    bits.push(qim_read(dct[idx], ROBUST_DELTA));
                }
            }
        }
    }

    // Untriple header
    let tripled = &bits[..TRIPLED_HEADER_BITS];
    let untripled = untriple_bits(tripled);
    if untripled.len() < FIXED_HEADER_BITS {
        return Err(anyhow!("header untriple short"));
    }
    let header = bits_to_bytes(&untripled[..FIXED_HEADER_BITS]);
    if header[0..4] != STEGO_MAGIC {
        let got: String = header[0..4].iter()
            .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("Robust header bad magic (got: {})", got));
    }
    let fec_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let name_len = header[17] as usize;
    let name_len = name_len.min(200);
    let payload_bits_needed = fec_len * 8;
    if TRIPLED_HEADER_BITS + payload_bits_needed > bits.len() {
        return Err(anyhow!("Robust payload overflow: need {}, have {}",
            TRIPLED_HEADER_BITS + payload_bits_needed, bits.len()));
    }
    let pay_bits = &bits[TRIPLED_HEADER_BITS..TRIPLED_HEADER_BITS + payload_bits_needed];
    let pay_bytes = bits_to_bytes(pay_bits);

    // Reconstruct original stream
    let mut out = Vec::with_capacity(18 + name_len + fec_len);
    out.extend_from_slice(&header[..18 + name_len]);
    out.extend_from_slice(&pay_bytes[..fec_len.min(pay_bytes.len())]);
    Ok(out)
}

// ---------------- Public API ----------------
pub fn embed(carrier: &DynamicImage, payload: &[u8], opts: &StegoOptions) -> Result<StegoOutcome> {
    let rgb = carrier.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("carrier too small (min {}x{})", MIN_SIDE, MIN_SIDE));
    }
    let cap = capacity_bytes_for(w, h, opts.mode);
    if payload.len() > cap {
        return Err(anyhow!("payload {} B > capacity {} B ({})",
            payload.len(), cap, opts.mode.short()));
    }
    let (stream, cipher) = build_stream(payload, opts)?;
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

/// Auto-detect: try BitPerfect, then Robust.
pub fn extract(stego: &DynamicImage, password: &str) -> Result<StegoExtract> {
    let rgb = stego.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("image too small"));
    }

    // 1. BitPerfect
    let lsb_raw = extract_bit_perfect(&rgb);
    if let Ok(r) = try_decode_stream(&lsb_raw, password) {
        return Ok(r);
    }

    // 2. Robust
    match extract_robust(&rgb) {
        Ok(stream) => try_decode_stream(&stream, password),
        Err(e_rob) => Err(anyhow!("LSB no match; Robust: {}", e_rob)),
    }
}