//! Audio steganography (FFT-OFDM QIM + BitPerfect LSB).
//!
//! Robust mode:
//!   - Split channel 0 into non-overlapping FFT_N-sample blocks
//!   - FFT, QIM on selected bin magnitudes, IFFT, replace block
//!   - Robust to MP3 320 / AAC 256 after re-encode
//!   - Bins chosen from [BINS_LO, BINS_HI) - high-mid, mostly masked
//!
//! Why FFT-OFDM instead of MDCT:
//!   MDCT is a TDAC codec - perfect reconstruction requires that the
//!   spectrum be unmodified. Any QIM modification breaks time-domain
//!   aliasing cancellation and corrupts neighboring frames. FFT with a
//!   fixed block grid avoids this entirely: encoder and decoder share the
//!   exact same block layout, so the modified magnitude is what comes back.
//!
//! BitPerfect mode:
//!   - LSB of channel-0 16-bit PCM samples
//!   - WAV / FLAC only (lossless)
//!
//! Stream format (FMSA) mirrors FMS3:
//!   [magic "FMSA"][fec_len u32 LE][flags u8][hash 8B][name_len u8]
//!   [name <=200][meta_len u16 LE][meta <=512]
//!   [sig_pub 32]?[sig 64]?[fec_data]

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rustfft::{FftPlanner, num_complex::Complex32};

use crate::audio::wav::WavFile;
use crate::crypto::{content_hash_8, CipherKind};
use crate::fec;

pub const FMSA_MAGIC: [u8; 4] = *b"FMSA";

// ---------- FFT-OFDM parameters ----------
pub const FFT_N: usize = 2048;
pub const BITS_PER_FRAME: usize = 32;
pub const BINS_LO: usize = 128;
pub const BINS_HI: usize = 640;
pub const BINS_RANGE: usize = BINS_HI - BINS_LO;
/// QIM step in raw FFT magnitude units (signal in [-1, 1]).
/// A full-amplitude sine at one bin gives magnitude ~ N/2 = 1024.
/// step=2 -> ~0.2% distortion on a strong tone, inaudible.
pub const QIM_STEP: f32 = 2.0;

const SIG_TOTAL: usize = 96;
/// Fixed stream header bytes (no name, no meta, no signature).
const STREAM_OVERHEAD_MIN: usize = 20; // magic(4)+fec_len(4)+flags(1)+hash(8)+name_len(1)+meta_len(2)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioMode { Robust, BitPerfect }
impl Default for AudioMode { fn default() -> Self { Self::Robust } }
impl AudioMode {
    pub fn label(&self) -> &'static str {
        match self { Self::Robust => "Robust (FFT-OFDM)", Self::BitPerfect => "BitPerfect (LSB PCM)" }
    }
}

#[derive(Debug, Clone)]
pub struct AudioEmbedOptions {
    pub password: String,
    pub mode: AudioMode,
    pub author: String,
    pub license: String,
    pub signing_seed: Option<[u8; 32]>,
    pub original_name: String,
}
impl Default for AudioEmbedOptions {
    fn default() -> Self {
        Self {
            password: String::new(),
            mode: AudioMode::Robust,
            author: String::new(),
            license: String::new(),
            signing_seed: None,
            original_name: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AudioEmbedOutcome {
    pub wav: WavFile,
    pub payload_bytes: usize,
    pub fec_bytes: usize,
    pub capacity_bytes: usize,
    pub cipher: CipherKind,
    pub content_hash: String,
    pub mode: AudioMode,
    pub signed: bool,
    pub signer_pubkey: String,
}

#[derive(Debug, Clone)]
pub struct AudioExtract {
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
pub fn capacity_bytes(w: &WavFile, mode: AudioMode) -> usize {
    if w.channels == 0 { return 0; }
    match mode {
        AudioMode::Robust => {
            let frames = w.frames() / FFT_N;
            let bits = frames * BITS_PER_FRAME;
            let raw = bits / 8;
            let after = raw.saturating_sub(STREAM_OVERHEAD_MIN);
            (after * 223) / 255
        }
        AudioMode::BitPerfect => {
            let samples_mono = w.frames();
            let raw = samples_mono / 8;
            let after = raw.saturating_sub(STREAM_OVERHEAD_MIN);
            (after * 223) / 255
        }
    }
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

// ---------- QIM ----------
fn qim_place(mag: f32, bit: u8, step: f32) -> f32 {
    let q = (mag / step).round() as i32;
    let p = ((q % 2) + 2) % 2;
    let target = if p == (bit as i32) {
        q
    } else if (mag - (q - 1) as f32 * step).abs() < (mag - (q + 1) as f32 * step).abs() {
        q - 1
    } else {
        q + 1
    };
    target as f32 * step
}
fn qim_read(mag: f32, step: f32) -> u8 {
    let q = (mag / step).round() as i32;
    (((q % 2) + 2) % 2) as u8
}

/// Deterministic bin selection for frame `frame_idx`.
/// 37 is coprime with BINS_RANGE (512 = 2^9), so indices are unique per frame.
fn frame_bins(frame_idx: usize) -> [usize; BITS_PER_FRAME] {
    let base = (frame_idx.wrapping_mul(17)) % BINS_RANGE;
    let mut out = [0usize; BITS_PER_FRAME];
    for i in 0..BITS_PER_FRAME {
        out[i] = BINS_LO + ((base + i * 37) % BINS_RANGE);
    }
    out
}

// ---------- Robust embed / extract (FFT-OFDM) ----------
fn embed_robust(samples: &mut [f32], channels: usize, stream: &[u8]) -> Result<()> {
    let bits = bytes_to_bits(stream);
    let n_mono = samples.len() / channels;
    let frames = n_mono / FFT_N;
    let slots = frames * BITS_PER_FRAME;
    if bits.len() > slots {
        return Err(anyhow!(
            "audio embed: need {} bits, {} slots available ({} frames)",
            bits.len(), slots, frames
        ));
    }

    let mut planner = FftPlanner::<f32>::new();
    let fft_fwd = planner.plan_fft_forward(FFT_N);
    let fft_inv = planner.plan_fft_inverse(FFT_N);
    let inv_scale = 1.0 / FFT_N as f32;

    let mut mono: Vec<f32> = (0..n_mono).map(|i| samples[i * channels]).collect();

    let mut bit_i = 0usize;
    for frame_idx in 0..frames {
        if bit_i >= bits.len() { break; }
        let start = frame_idx * FFT_N;
        let mut buf: Vec<Complex32> = (0..FFT_N)
            .map(|i| Complex32::new(mono[start + i], 0.0))
            .collect();
        fft_fwd.process(&mut buf);

        let bins = frame_bins(frame_idx);
        for &k in bins.iter() {
            if bit_i >= bits.len() { break; }
            let mag = buf[k].norm();
            let new_mag = qim_place(mag, bits[bit_i], QIM_STEP);
            if mag > 1e-9 {
                let scale = new_mag / mag;
                buf[k] *= scale;
                buf[FFT_N - k] = buf[k].conj();
            }
            bit_i += 1;
        }

        fft_inv.process(&mut buf);
        for i in 0..FFT_N {
            mono[start + i] = (buf[i].re * inv_scale).clamp(-1.0, 1.0);
        }
    }

    for i in 0..n_mono { samples[i * channels] = mono[i]; }
    Ok(())
}

fn extract_robust(samples: &[f32], channels: usize) -> Vec<u8> {
    let n_mono = samples.len() / channels;
    let frames = n_mono / FFT_N;

    let mut planner = FftPlanner::<f32>::new();
    let fft_fwd = planner.plan_fft_forward(FFT_N);

    let mono: Vec<f32> = (0..n_mono).map(|i| samples[i * channels]).collect();
    let mut bits: Vec<u8> = Vec::with_capacity(frames * BITS_PER_FRAME);
    let mut target_bits: Option<usize> = None;

    for frame_idx in 0..frames {
        if let Some(tb) = target_bits { if bits.len() >= tb { break; } }
        let start = frame_idx * FFT_N;
        let mut buf: Vec<Complex32> = (0..FFT_N)
            .map(|i| Complex32::new(mono[start + i], 0.0))
            .collect();
        fft_fwd.process(&mut buf);

        let bins = frame_bins(frame_idx);
        for &k in bins.iter() {
            let mag = buf[k].norm();
            bits.push(qim_read(mag, QIM_STEP));
        }

        // Peek FMSA header once we have 24 bytes.
        if target_bits.is_none() && bits.len() >= 24 * 8 {
            let head = bits_to_bytes(&bits[..24 * 8]);
            if head[0..4] == FMSA_MAGIC {
                let fec_len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
                let flags = head[8];
                let name_len = (head[17] as usize).min(200);
                let sig_total = if flags & 4 != 0 { SIG_TOTAL } else { 0 };
                let meta_upper = 512usize;
                let total_bytes = 20 + name_len + meta_upper + sig_total + fec_len;
                target_bits = Some(total_bytes * 8);
            }
        }
    }
    bits_to_bytes(&bits)
}

// ---------- BitPerfect ----------
fn embed_bit_perfect(samples: &mut [f32], channels: usize, stream: &[u8]) -> Result<()> {
    let bits = bytes_to_bits(stream);
    let n_mono = samples.len() / channels;
    let mut i = 0usize;
    for f in 0..n_mono {
        if i >= bits.len() { break; }
        let s = samples[f * channels];
        let v = (s * 32768.0).clamp(-32768.0, 32767.0) as i32;
        let v = (v & !1) | (bits[i] as i32);
        samples[f * channels] = (v as f32) / 32768.0;
        i += 1;
    }
    if i < bits.len() { return Err(anyhow!("bitperfect: only wrote {} of {} bits", i, bits.len())); }
    Ok(())
}

fn extract_bit_perfect(samples: &[f32], channels: usize) -> Vec<u8> {
    let n_mono = samples.len() / channels;
    let mut bits = Vec::with_capacity(n_mono);
    for f in 0..n_mono {
        let s = samples[f * channels];
        let v = (s * 32768.0).round() as i32;
        bits.push((v & 1) as u8);
    }
    bits_to_bytes(&bits)
}

// ---------- Stream construction (FMSA) ----------
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

fn build_meta(opts: &AudioEmbedOptions, hash: &[u8; 8]) -> Vec<u8> {
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
    s.push_str(",\"v\":1}");
    s.into_bytes()
}

fn build_stream(payload: &[u8], opts: &AudioEmbedOptions) -> Result<(Vec<u8>, CipherKind, bool, String)> {
    let (enc_bytes, cipher) = if opts.password.is_empty() {
        (payload.to_vec(), CipherKind::None)
    } else {
        let sealed = crate::crypto::seal::seal(&opts.password, payload, crate::crypto::SealMode::Padded)?;
        (sealed, CipherKind::SealV1)
    };
    let fec_data = fec::encode(&enc_bytes)?;
    let hash = content_hash_8(payload);
    let meta = build_meta(opts, &hash);
    let meta_len = meta.len().min(512);
    let meta_bytes = &meta[..meta_len];

    let (sig_pub, sig_bytes, signed, pubkey_hex) = if let Some(seed) = opts.signing_seed {
        let sk = SigningKey::from_bytes(&seed);
        let vk: VerifyingKey = sk.verifying_key();
        let sig = sk.sign(meta_bytes).to_bytes();
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(vk.as_bytes());
        (pub_arr, sig, true, hex::encode(pub_arr))
    } else {
        ([0u8; 32], [0u8; 64], false, String::new())
    };

    let mut flags: u8 = match cipher { CipherKind::None => 0, _ => 1 };
    if meta_len > 0 { flags |= 2; }
    if signed { flags |= 4; }

    let name_bytes = opts.original_name.as_bytes();
    let name_len = name_bytes.len().min(200);

    let mut out = Vec::with_capacity(20 + name_len + meta_len + if signed { SIG_TOTAL } else { 0 } + fec_data.len());
    out.extend_from_slice(&FMSA_MAGIC);
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
        if let Some(end) = json[start..].find('"') { return json[start..start + end].to_string(); }
    }
    String::new()
}
fn extract_json_u32(json: &str, key: &str) -> u32 {
    let needle = format!("\"{}\":", key);
    if let Some(pos) = json.find(&needle) {
        let rest = &json[pos + needle.len()..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        return rest[..end].parse().unwrap_or(0);
    }
    0
}

fn try_decode_stream(raw: &[u8], password: &str) -> Result<AudioExtract> {
    if raw.len() < 20 { return Err(anyhow!("audio stream too short")); }
    if raw[0..4] != FMSA_MAGIC {
        let got: String = raw[0..4].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        return Err(anyhow!("no FMSA magic (got: {})", got));
    }
    let fec_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let flags = raw[8];
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&raw[9..17]);
    let name_len = (raw[17] as usize).min(200);
    if 18 + name_len + 2 > raw.len() { return Err(anyhow!("name overflow")); }
    let name = if name_len > 0 { String::from_utf8_lossy(&raw[18..18 + name_len]).to_string() } else { String::new() };
    let meta_off = 18 + name_len;
    let meta_len = u16::from_le_bytes([raw[meta_off], raw[meta_off + 1]]) as usize;
    let meta_start = meta_off + 2;
    if meta_start + meta_len > raw.len() { return Err(anyhow!("meta overflow")); }
    let meta_str = String::from_utf8_lossy(&raw[meta_start..meta_start + meta_len]).to_string();
    let author = extract_json_field(&meta_str, "author");
    let license = extract_json_field(&meta_str, "license");
    let ts = extract_json_u32(&meta_str, "ts");

    let mut sig_end = meta_start + meta_len;
    let (signature_ok, signer_pubkey) = if flags & 4 != 0 {
        if sig_end + SIG_TOTAL > raw.len() { return Err(anyhow!("signature overflow")); }
        let pub_arr: [u8; 32] = raw[sig_end..sig_end + 32].try_into().unwrap();
        let sig_arr: [u8; 64] = raw[sig_end + 32..sig_end + SIG_TOTAL].try_into().unwrap();
        sig_end += SIG_TOTAL;
        let pub_hex = hex::encode(pub_arr);
        let ok = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(vk) => {
                let s = Signature::from_bytes(&sig_arr);
                vk.verify(&raw[meta_start..meta_start + meta_len], &s).is_ok()
            }
            Err(_) => false,
        };
        (Some(ok), pub_hex)
    } else { (None, String::new()) };

    let fec_start = sig_end;
    if fec_start + fec_len > raw.len() { return Err(anyhow!("payload truncated")); }
    let fec_bytes = &raw[fec_start..fec_start + fec_len];
    let enc = fec::decode(fec_bytes).map_err(|e| anyhow!("fec: {}", e))?;
    let payload = if flags & 1 != 0 {
        if password.is_empty() { return Err(anyhow!("password required")); }
        crate::crypto::seal::open(password, &enc).map_err(|_| anyhow!("wrong password"))?
    } else { enc };
    let expect = content_hash_8(&payload);
    if expect != hash { return Err(anyhow!("hash mismatch")); }
    let cipher = if flags & 1 != 0 { CipherKind::SealV1 } else { CipherKind::None };
    Ok(AudioExtract {
        payload, name, cipher,
        content_hash: hex::encode(hash),
        author, license, timestamp: ts,
        signature_ok, signer_pubkey,
    })
}

// ---------- Public API ----------
pub fn embed_wav(carrier: &WavFile, payload: &[u8], opts: &AudioEmbedOptions) -> Result<AudioEmbedOutcome> {
    if carrier.channels == 0 { return Err(anyhow!("no channels")); }
    let cap = capacity_bytes(carrier, opts.mode);
    if payload.len() > cap {
        return Err(anyhow!("payload {} B > capacity {} B ({})", payload.len(), cap, opts.mode.label()));
    }
    let (stream, cipher, signed, pubkey_hex) = build_stream(payload, opts)?;

    // Real check: does the FULL stream fit in the available slots?
    let n_mono = carrier.samples.len() / carrier.channels as usize;
    let (avail_bits, mode_label) = match opts.mode {
        AudioMode::Robust     => ((n_mono / FFT_N) * BITS_PER_FRAME, "FFT-OFDM"),
        AudioMode::BitPerfect => (n_mono, "LSB PCM"),
    };
    if stream.len() * 8 > avail_bits {
        return Err(anyhow!(
            "stream {} bits > {} slots ({}); reduce payload or use longer audio",
            stream.len() * 8, avail_bits, mode_label
        ));
    }

    let mut out = carrier.samples.clone();
    let channels = carrier.channels as usize;
    match opts.mode {
        AudioMode::Robust => embed_robust(&mut out, channels, &stream)?,
        AudioMode::BitPerfect => embed_bit_perfect(&mut out, channels, &stream)?,
    }

    Ok(AudioEmbedOutcome {
        wav: WavFile {
            sample_rate: carrier.sample_rate,
            channels: carrier.channels,
            bits_per_sample: carrier.bits_per_sample,
            samples: out,
        },
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

pub fn extract_wav(stego: &WavFile, password: &str) -> Result<AudioExtract> {
    if stego.channels == 0 { return Err(anyhow!("no channels")); }
    let channels = stego.channels as usize;

    let robust_raw = extract_robust(&stego.samples, channels);
    if let Ok(r) = try_decode_stream(&robust_raw, password) { return Ok(r); }

    let bp_raw = extract_bit_perfect(&stego.samples, channels);
    if let Ok(r) = try_decode_stream(&bp_raw, password) { return Ok(r); }

    Err(anyhow!("no FMSA stream found (tried Robust + BitPerfect)"))
}