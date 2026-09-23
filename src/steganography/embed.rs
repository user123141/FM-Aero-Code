//! Steganography v3.9.4 - FMS3 with Ed25519 signatures and timestamp.
//!
//! Stream layout (FMS3):
//!   [magic 4 = "FMS3"]
//!   [fec_len 4 LE]
//!   [flags 1]              bit0=encrypted, bit1=has_meta, bit2=signed
//!   [hash 8]               SHA-256[:8] of payload
//!   [name_len 1]
//!   [name <=200]
//!   [meta_len 2 LE]
//!   [meta <=512]           JSON: {author,license,ts,hash,v}
//!   [sig_pub 32]           only if flag 4
//!   [sig 64]               only if flag 4
//!   [fec_data]

use anyhow::{anyhow, Result};
use image::{DynamicImage, RgbImage};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

use crate::crypto::{CipherKind, content_hash_8};
use crate::fec;
use crate::steganography::dct::{dct8x8, idct8x8, BLOCK_AREA};
use crate::steganography::STEGO_MAGIC;

const MIN_SIDE: u32 = 64;
const ROBUST_IDX: [usize; 12] = [1, 8, 9, 2, 3, 10, 16, 17, 4, 11, 18, 24];
const ROBUST_DELTA_SET: [f32; 4] = [18.0, 22.0, 26.0, 30.0];
const ROBUST_REFINE: usize = 8;

const FIXED_HEADER_BYTES: usize = 218;
const FIXED_HEADER_BITS: usize = FIXED_HEADER_BYTES * 8;
const HEADER_COPIES: usize = 4;
const MULTIPLIED_HEADER_BITS: usize = FIXED_HEADER_BITS * HEADER_COPIES;

const SIG_PUB_LEN: usize = 32;
const SIG_LEN: usize = 64;
const SIG_TOTAL: usize = SIG_PUB_LEN + SIG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoMode { BitPerfect, Robust, DualB }
impl Default for StegoMode { fn default() -> Self { Self::BitPerfect } }
impl StegoMode {
    pub fn label(&self) -> &'static str {
        match self { Self::BitPerfect => "BitPerfect (PNG)", Self::Robust => "Robust (JPEG)", Self::DualB => "DualB (layered)" }
    }
    pub fn short(&self) -> &'static str {
        match self { Self::BitPerfect => "BitPerfect", Self::Robust => "Robust", Self::DualB => "DualB" }
    }
}

#[derive(Debug, Clone)]
pub struct StegoOptions {
    pub password: String,
    pub original_name: String,
    pub mode: StegoMode,
    pub author: String,
    pub license: String,
    /// 32-byte Ed25519 seed for signing. None = no signature.
    pub signing_seed: Option<[u8; 32]>,
}
impl Default for StegoOptions {
    fn default() -> Self {
        Self {
            password: String::new(),
            original_name: String::new(),
            mode: StegoMode::BitPerfect,
            author: String::new(),
            license: String::new(),
            signing_seed: None,
        }
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
    pub signed: bool,
    pub signer_pubkey: String,
}

#[derive(Debug, Clone)]
pub struct StegoExtract {
    pub payload: Vec<u8>,
    pub name: String,
    pub cipher: CipherKind,
    pub content_hash: String,
    pub author: String,
    pub license: String,
    pub timestamp: u32,
    pub signature_ok: Option<bool>,
    pub signer_pubkey: String,
}

// ---------- Capacity ----------
pub fn capacity_bytes(w: u32, h: u32) -> usize {
    capacity_bytes_for(w, h, StegoMode::BitPerfect)
}
/// Max stream overhead bytes inside the visible stream (before fec_data):
/// magic(4) + fec_len(4) + flags(1) + hash(8) + name_len(1) + name(<=200)
/// + meta_len(2) + meta(<=512) + sig(96)
const STREAM_OVERHEAD_MAX: usize = 4 + 4 + 1 + 8 + 1 + 200 + 2 + 512 + SIG_TOTAL;

pub fn capacity_bytes_for(w: u32, h: u32, mode: StegoMode) -> usize {
    match mode {
        StegoMode::BitPerfect => {
            let bits = (w as usize) * (h as usize) * 3;
            let raw = bits / 8;
            let after = raw.saturating_sub(STREAM_OVERHEAD_MAX);
            (after * 223) / 255
        }
        StegoMode::Robust => {
            let blocks = (w as usize / 8) * (h as usize / 8);
            let slots = blocks * ROBUST_IDX.len();
            let payload_slots = slots.saturating_sub(MULTIPLIED_HEADER_BITS);
            let payload_stream_bytes = payload_slots / 8;
            let fec_max = payload_stream_bytes.saturating_sub(STREAM_OVERHEAD_MAX);
            (fec_max * 223) / 255
        }
        StegoMode::DualB => {
            let bits = (w as usize) * (h as usize);
            let raw = bits / 8;
            let after = raw.saturating_sub(STREAM_OVERHEAD_MAX);
            (after * 223) / 255
        }
    }
}

// ---------- Stream ----------
fn escape_json(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o
}

fn build_meta(opts: &StegoOptions, hash: &[u8; 8]) -> Vec<u8> {
    let mut s = String::from("{");
    let mut first = true;
    if !opts.author.is_empty() {
        s.push_str("\"author\":\"");
        s.push_str(&escape_json(&opts.author));
        s.push('"');
        first = false;
    }
    if !opts.license.is_empty() {
        if !first { s.push(','); }
        s.push_str("\"license\":\"");
        s.push_str(&escape_json(&opts.license));
        s.push('"');
        first = false;
    }
    if !first { s.push(','); }
    s.push_str("\"hash\":\"");
    s.push_str(&hex::encode(hash));
    s.push_str("\",\"ts\":");
    s.push_str(&crate::types::now_unix().to_string());
    s.push_str(",\"v\":3}");
    s.into_bytes()
}

fn build_stream(payload: &[u8], opts: &StegoOptions) -> Result<(Vec<u8>, CipherKind, bool, String)> {
    let (enc_bytes, cipher) = if opts.password.is_empty() {
        (payload.to_vec(), CipherKind::None)
    } else {
        let sealed = crate::crypto::seal::seal(
            &opts.password, payload, crate::crypto::SealMode::Padded,
        )?;
        (sealed, CipherKind::SealV1)
    };
    let fec_data = fec::encode(&enc_bytes)?;
    let hash = content_hash_8(payload);

    let meta = build_meta(opts, &hash);
    let meta_len = meta.len().min(512);
    let meta_bytes = &meta[..meta_len];

    // Signing
    let (sig_pub, sig_bytes, signed, pubkey_hex) = if let Some(seed) = opts.signing_seed {
        let sk = SigningKey::from_bytes(&seed);
        let vk: VerifyingKey = sk.verifying_key();
        let sig = sk.sign(meta_bytes);
        let sig_arr = sig.to_bytes();
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(vk.as_bytes());
        (pub_arr, sig_arr, true, hex::encode(pub_arr))
    } else {
        ([0u8; 32], [0u8; 64], false, String::new())
    };

    let mut flags: u8 = match cipher { CipherKind::None => 0, _ => 1 };
    if meta_len > 0 { flags |= 2; }
    if signed { flags |= 4; }

    let name_bytes = opts.original_name.as_bytes();
    let name_len = name_bytes.len().min(200);

    let mut out = Vec::with_capacity(20 + name_len + meta_len + if signed { SIG_TOTAL } else { 0 } + fec_data.len());
    out.extend_from_slice(&STEGO_MAGIC);
    out.extend_from_slice(&(fec_data.len() as u32).to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&hash);
    out.push(name_len as u8);
    out.extend_from_slice(&name_bytes[..name_len]);
    out.extend_from_slice(&(meta_len as u16).to_le_bytes());
    out.extend_from_slice(meta_bytes);
    if signed {
        out.extend_from_slice(&sig_pub);
        out.extend_from_slice(&sig_bytes);
    }
    out.extend_from_slice(&fec_data);
    Ok((out, cipher, signed, pubkey_hex))
}

fn extract_json_field(json: &str, key: &str) -> String {
    let needle = format!("\"{}\":\"", key);
    if let Some(pos) = json.find(&needle) {
        let start = pos + needle.len();
        if let Some(end_rel) = json[start..].find('"') {
            return json[start..start + end_rel].to_string();
        }
    }
    String::new()
}

fn extract_json_u32(json: &str, key: &str) -> u32 {
    let needle = format!("\"{}\":", key);
    if let Some(pos) = json.find(&needle) {
        let start = pos + needle.len();
        let rest = &json[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        return rest[..end].parse().unwrap_or(0);
    }
    0
}

fn try_decode_stream(raw: &[u8], password: &str) -> Result<StegoExtract> {
    if raw.len() < 20 {
        return Err(anyhow!("stream too short ({} bytes)", raw.len()));
    }
    if raw[0..4] != STEGO_MAGIC {
        let got: String = raw[0..4].iter()
            .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("no FMS3 magic (got: {})", got));
    }
    let fec_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let flags = raw[8];
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&raw[9..17]);
    let name_len = (raw[17] as usize).min(200);
    if 18 + name_len + 2 > raw.len() {
        return Err(anyhow!("name overflow"));
    }
    let name = if name_len > 0 {
        String::from_utf8_lossy(&raw[18..18 + name_len]).to_string()
    } else { String::new() };
    let meta_off = 18 + name_len;
    let meta_len = u16::from_le_bytes([raw[meta_off], raw[meta_off + 1]]) as usize;
    let meta_start = meta_off + 2;
    if meta_start + meta_len > raw.len() {
        return Err(anyhow!("meta overflow"));
    }
    let meta_str = String::from_utf8_lossy(&raw[meta_start..meta_start + meta_len]).to_string();
    let author = extract_json_field(&meta_str, "author");
    let license = extract_json_field(&meta_str, "license");
    let ts = extract_json_u32(&meta_str, "ts");

    let mut sig_end = meta_start + meta_len;
    let (signature_ok, signer_pubkey) = if flags & 4 != 0 {
        if sig_end + SIG_TOTAL > raw.len() {
            return Err(anyhow!("signature overflow"));
        }
        let pub_arr: [u8; 32] = raw[sig_end..sig_end + 32].try_into().unwrap();
        let sig_arr: [u8; 64] = raw[sig_end + 32..sig_end + SIG_TOTAL].try_into().unwrap();
        sig_end += SIG_TOTAL;
        let pub_hex = hex::encode(pub_arr);
        let ok = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(vk) => match Signature::from_bytes(&sig_arr) {
                s => vk.verify(&raw[meta_start..meta_start + meta_len], &s).is_ok(),
            },
            Err(_) => false,
        };
        (Some(ok), pub_hex)
    } else {
        (None, String::new())
    };

    let fec_start = sig_end;
    if fec_start + fec_len > raw.len() {
        return Err(anyhow!("payload truncated"));
    }
    let fec_bytes = &raw[fec_start..fec_start + fec_len];
    let enc = fec::decode(fec_bytes).map_err(|e| anyhow!("fec: {}", e))?;
    let payload = if flags & 1 != 0 {
        if password.is_empty() { return Err(anyhow!("password required")); }
        crate::crypto::seal::open(password, &enc)
            .map_err(|_| anyhow!("wrong password"))?
    } else { enc };
    let expect = content_hash_8(&payload);
    if expect != hash {
        return Err(anyhow!("hash mismatch"));
    }
    let cipher = if flags & 1 != 0 { CipherKind::SealV1 } else { CipherKind::None };
    Ok(StegoExtract {
        payload, name, cipher,
        content_hash: hex::encode(hash),
        author, license, timestamp: ts,
        signature_ok, signer_pubkey,
    })
}

// ---------- Bit helpers ----------
fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes { for k in (0..8).rev() { out.push((b >> k) & 1); } }
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
fn multiply_bits(bits: &[u8], copies: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len() * copies);
    for &b in bits { for _ in 0..copies { out.push(b); } }
    out
}
fn demultiply_bits(mult: &[u8], copies: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(mult.len() / copies);
    for chunk in mult.chunks(copies) {
        if chunk.len() < copies { break; }
        let s: u32 = chunk.iter().map(|&b| b as u32).sum();
        let threshold = (copies / 2) as u32 + 1;
        out.push(if s >= threshold { 1 } else { 0 });
    }
    out
}

// ---------- BitPerfect ----------
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

// ---------- Robust ----------
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
    let mut hdr = vec![0u8; FIXED_HEADER_BYTES];
    let copy_len = stream.len().min(FIXED_HEADER_BYTES);
    hdr[..copy_len].copy_from_slice(&stream[..copy_len]);
    let payload = if stream.len() > FIXED_HEADER_BYTES {
        stream[FIXED_HEADER_BYTES..].to_vec()
    } else { Vec::new() };
    (hdr, payload)
}

fn embed_robust_with_delta(mut rgb: RgbImage, stream: &[u8], delta: f32) -> Result<RgbImage> {
    let (hdr, payload) = split_stream(stream);
    let mut all_bits = multiply_bits(&bytes_to_bits(&hdr), HEADER_COPIES);
    all_bits.extend_from_slice(&bytes_to_bits(&payload));

    let (w, h) = (rgb.width(), rgb.height());
    let bw = (w / 8) as usize;
    let bh = (h / 8) as usize;
    let mut bit_i = 0usize;

    for byi in 0..bh {
        for bxi in 0..bw {
            if bit_i >= all_bits.len() { break; }
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
            let bstart = bit_i;
            for &idx in ROBUST_IDX.iter() {
                if bit_i >= all_bits.len() { break; }
                dct[idx] = qim_place(dct[idx], all_bits[bit_i], delta);
                bit_i += 1;
            }
            let bend = bit_i;
            for _ in 0..ROBUST_REFINE {
                let mut sp = [0.0f32; BLOCK_AREA];
                idct8x8(&dct, &mut sp);
                let mut spi = [0u8; BLOCK_AREA];
                for i in 0..BLOCK_AREA { spi[i] = sp[i].round().clamp(0.0, 255.0) as u8; }
                let mut spf = [0.0f32; BLOCK_AREA];
                for i in 0..BLOCK_AREA { spf[i] = spi[i] as f32; }
                let mut verify = [0.0f32; BLOCK_AREA];
                dct8x8(&spf, &mut verify);
                let mut ok = true;
                for (k, &idx) in ROBUST_IDX.iter().enumerate() {
                    let bi = bstart + k;
                    if bi >= bend { break; }
                    if qim_read(verify[idx], delta) != all_bits[bi] {
                        ok = false;
                        let diff = verify[idx] - dct[idx];
                        let target = qim_place(verify[idx], all_bits[bi], delta);
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
                    rgb.get_pixel_mut(x0 + xx as u32, y0 + yy as u32).0[0] = v;
                }
            }
        }
    }
    if bit_i < all_bits.len() {
        return Err(anyhow!("Robust wrote {} of {} bits", bit_i, all_bits.len()));
    }
    Ok(rgb)
}

fn extract_robust_with_delta(rgb: &RgbImage, delta: f32) -> Result<Vec<u8>> {
    let (w, h) = (rgb.width(), rgb.height());
    let bw = (w / 8) as usize;
    let bh = (h / 8) as usize;
    let total_bits = bw * bh * ROBUST_IDX.len();
    if total_bits < MULTIPLIED_HEADER_BITS {
        return Err(anyhow!("not enough slots"));
    }
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for byi in 0..bh {
        for bxi in 0..bw {
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
            for &idx in ROBUST_IDX.iter() {
                bits.push(qim_read(dct[idx], delta));
            }
        }
    }
    let mult = &bits[..MULTIPLIED_HEADER_BITS];
    let demult = demultiply_bits(mult, HEADER_COPIES);
    let header = bits_to_bytes(&demult[..FIXED_HEADER_BITS]);
    if header[0..4] != STEGO_MAGIC {
        let got: String = header[0..4].iter()
            .map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("Robust header bad magic (got: {})", got));
    }
    let fec_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let name_len = (header[17] as usize).min(200);
    let meta_len_off = 18 + name_len;
    if meta_len_off + 2 > FIXED_HEADER_BYTES { return Err(anyhow!("header layout bad")); }
    let meta_len = u16::from_le_bytes([header[meta_len_off], header[meta_len_off + 1]]) as usize;
    let flags = header[8];
    let sig_extra = if flags & 4 != 0 { SIG_TOTAL } else { 0 };
    let header_used = meta_len_off + 2 + meta_len + sig_extra;
    if header_used > FIXED_HEADER_BYTES {
        return Err(anyhow!("header_used {} > {}", header_used, FIXED_HEADER_BYTES));
    }
    let payload_bits_needed = fec_len * 8;
    if MULTIPLIED_HEADER_BITS + payload_bits_needed > bits.len() {
        return Err(anyhow!("payload overflow"));
    }
    let pay_bits = &bits[MULTIPLIED_HEADER_BITS..MULTIPLIED_HEADER_BITS + payload_bits_needed];
    let pay_bytes = bits_to_bytes(pay_bits);
    let mut out = Vec::with_capacity(FIXED_HEADER_BYTES + fec_len);
    out.extend_from_slice(&header[..FIXED_HEADER_BYTES]);
    out.extend_from_slice(&pay_bytes[..fec_len.min(pay_bytes.len())]);
    Ok(out)
}

// ---------- DualB: B-channel-only LSB (coexists with AeroGlint grayscale) ----------
fn embed_dual_b(mut rgb: RgbImage, stream: &[u8]) -> Result<RgbImage> {
    let bits = bytes_to_bits(stream);
    let (w, h) = (rgb.width(), rgb.height());
    let mut i = 0usize;
    'outer: for y in 0..h {
        for x in 0..w {
            if i >= bits.len() { break 'outer; }
            let px = rgb.get_pixel_mut(x, y);
            px.0[2] = (px.0[2] & 0xFE) | bits[i];
            i += 1;
        }
    }
    if i < bits.len() { return Err(anyhow!("DualB overflow")); }
    Ok(rgb)
}

fn extract_dual_b(rgb: &RgbImage) -> Vec<u8> {
    let (w, h) = (rgb.width(), rgb.height());
    let mut bits = Vec::with_capacity((w as usize) * (h as usize));
    for y in 0..h {
        for x in 0..w {
            bits.push(rgb.get_pixel(x, y).0[2] & 1);
        }
    }
    bits_to_bytes(&bits)
}

// ---------- Public API ----------

pub fn embed(carrier: &DynamicImage, payload: &[u8], opts: &StegoOptions) -> Result<StegoOutcome> {
    let rgb = carrier.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE {
        return Err(anyhow!("carrier too small"));
    }
    let cap = capacity_bytes_for(w, h, opts.mode);
    if payload.len() > cap {
        return Err(anyhow!("payload {} B > capacity {} B ({})",
            payload.len(), cap, opts.mode.short()));
    }
    let (stream, cipher, signed, pubkey_hex) = build_stream(payload, opts)?;

    let out_image = match opts.mode {
        StegoMode::BitPerfect => embed_bit_perfect(rgb, &stream)?,
        StegoMode::DualB => embed_dual_b(rgb, &stream)?,
        StegoMode::Robust => {
            let mut chosen: Option<RgbImage> = None;
            let mut last = String::from("no delta");
            for &d in ROBUST_DELTA_SET.iter() {
                let candidate = rgb.clone();
                match embed_robust_with_delta(candidate, &stream, d) {
                    Ok(img) => {
                        match extract_robust_with_delta(&img, d) {
                            Ok(_) => { chosen = Some(img); break; }
                            Err(e) => { last = format!("delta={}: {}", d, e); }
                        }
                    }
                    Err(e) => { last = format!("delta={}: {}", d, e); }
                }
            }
            chosen.ok_or_else(|| anyhow!("Robust failed ({})", last))?
        }
    };

    Ok(StegoOutcome {
        image: out_image,
        payload_bytes: payload.len(),
        fec_bytes: stream.len(),
        capacity_bytes: cap,
        cipher,
        content_hash: hex::encode(content_hash_8(payload)),
        mode: opts.mode,
        signed,
        signer_pubkey: pubkey_hex,
    })
}

pub fn extract(stego: &DynamicImage, password: &str) -> Result<StegoExtract> {
    let rgb = stego.to_rgb8();
    let (w, h) = (rgb.width(), rgb.height());
    if w < MIN_SIDE || h < MIN_SIDE { return Err(anyhow!("image too small")); }

    let lsb_raw = extract_bit_perfect(&rgb);
    if let Ok(r) = try_decode_stream(&lsb_raw, password) { return Ok(r); }

    let dualb_raw = extract_dual_b(&rgb);
    if let Ok(r) = try_decode_stream(&dualb_raw, password) { return Ok(r); }

    let mut last = String::from("no delta");
    for &d in ROBUST_DELTA_SET.iter() {
        match extract_robust_with_delta(&rgb, d) {
            Ok(stream) => match try_decode_stream(&stream, password) {
                Ok(r) => return Ok(r),
                Err(e) => { last = format!("delta={}: {}", d, e); }
            },
            Err(e) => { last = format!("delta={}: {}", d, e); }
        }
    }
    Err(anyhow!("LSB no match; Robust all failed ({})", last))
}

/// Generate a new Ed25519 keypair (seed, pubkey) as hex.
pub fn generate_signing_keypair() -> (String, String) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (hex::encode(seed), hex::encode(vk.as_bytes()))
}