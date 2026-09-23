use anyhow::{anyhow, Result};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use ed25519_dalek::SigningKey;

use crate::crypto::{CipherKind, content_hash_8, hmac_sha256, seal, seal2, sign_header, SealMode};
use crate::encoder::aeroglint::encode_stream;
use crate::encoder::compressor::{aero_pack, aero_pack_lossless, aero_unpack, classify, DataProfile};
use crate::fastmem::assert_size;
use crate::types::{
    AeroHeader, CompressionKind, DataType, ResilienceLevel, AERO_HEADER_SIZE,
    HEADER_FLAG_GAMMA, HEADER_FLAG_HMAC, HEADER_FLAG_MULTIPAGE, HEADER_FLAG_NAMED,
    HEADER_FLAG_PADDED, HEADER_FLAG_SIGNED, fnv32,
};
use crate::MAX_COMPRESSED_BYTES;

const FILENAME_MAX_LEN: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMode { Auto, Lossless, LosslessPriority }
impl Default for CompressionMode { fn default() -> Self { Self::LosslessPriority } }
impl CompressionMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "Auto (AeroPack v20)",
            Self::Lossless => "Lossless (bit-perfect)",
            Self::LosslessPriority => "Lossless Priority (media-aware)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncodeOptions {
    pub cipher: CipherKind,
    pub password: String,
    pub pad: bool,
    pub compression: CompressionMode,
    pub original_name: String,
    pub center_logo: Option<Vec<u8>>,
    pub signing_key: Option<SigningKey>,
    pub hmac_enabled: bool,
    pub auto_lossless_media: bool,
    pub recipient_key: Option<String>,
    pub recipients: Vec<String>,
    pub gps: Option<(f64, f64)>,
    pub resilience_level: u8,
    pub border: bool,
    pub gamma: bool,
    pub mask: bool,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self {
            cipher: CipherKind::SealV1,
            password: String::new(),
            pad: true,
            compression: CompressionMode::LosslessPriority,
            original_name: String::new(),
            center_logo: None,
            signing_key: None,
            hmac_enabled: true,
            auto_lossless_media: true,
            recipient_key: None,
            recipients: Vec::new(),
            gps: None,
            resilience_level: 0,
            border: false,
            gamma: false,
            mask: false,
        }
    }
}

#[derive(Clone)]
pub struct EncodeOutcome {
    pub image: image::GrayImage,
    pub payload_bytes: usize,
    pub compressed_bytes: usize,
    pub data_type: DataType,
    pub cipher: CipherKind,
    pub content_hash: String,
    pub profile: DataProfile,
    pub ratio: f64,
}

#[derive(Clone)]
pub struct FlowOutcome {
    pub frames: Vec<image::GrayImage>,
    pub page_count: usize,
    pub payload_bytes: usize,
    pub compressed_bytes: usize,
    pub data_type: DataType,
    pub cipher: CipherKind,
    pub content_hash: String,
    pub profile: DataProfile,
    pub resilience_level: u8,
    pub num_groups: usize,
    pub data_pages_per_group: usize,
    pub parity_pages_per_group: usize,
}

struct Prepared {
    stream: Vec<u8>,
    effective_size: usize,
    content_hash: [u8; 8],
    data_type: DataType,
    profile: DataProfile,
    cipher: CipherKind,
    has_name: bool,
    used_lossless: bool,
    padded: bool,
}

fn is_already_compressed(data: &[u8]) -> bool {
    if data.len() < 8 { return false; }
    matches!(DataType::detect(data),
        DataType::Audio | DataType::Image | DataType::Video | DataType::Archive)
}

fn with_filename(payload: &[u8], name: &str) -> (Vec<u8>, bool) {
    if name.is_empty() { return (payload.to_vec(), false); }
    let bytes = name.as_bytes();
    let len = bytes.len().min(FILENAME_MAX_LEN);
    let mut out = Vec::with_capacity(1 + len + payload.len());
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
    out.extend_from_slice(payload);
    (out, true)
}

pub fn strip_filename(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    if payload.is_empty() { return None; }
    let n = payload[0] as usize;
    if payload.len() < 1 + n { return None; }
    let name = String::from_utf8_lossy(&payload[1..1 + n]).to_string();
    Some((name, payload[1 + n..].to_vec()))
}

fn prepare(payload: &[u8], opts: &EncodeOptions) -> Result<Prepared> {
    assert_size(payload.len(), MAX_COMPRESSED_BYTES)?;
    let data_type = DataType::detect(payload);
    let class = classify(payload);
    let already = is_already_compressed(payload);
    let effective_mode = match opts.compression {
        CompressionMode::LosslessPriority => if already { CompressionMode::Lossless } else { CompressionMode::Auto },
        CompressionMode::Auto if opts.auto_lossless_media && already => CompressionMode::Lossless,
        m => m,
    };
    let profile = if data_type.is_media() || matches!(data_type, DataType::Archive) {
        DataProfile::from_class(class)
    } else {
        crate::encoder::compressor::analyze(payload)
    };
    let cipher = if opts.password.is_empty() && opts.recipient_key.is_none() && opts.recipients.is_empty() {
        CipherKind::None
    } else if !opts.recipients.is_empty() || opts.recipient_key.is_some() {
        CipherKind::SealV2
    } else {
        CipherKind::SealV1
    };
    let content_hash = content_hash_8(payload);
    let (with_meta, has_name) = with_filename(payload, &opts.original_name);
    let mut framed = with_meta;
    let effective_size = framed.len();
    let do_pad = opts.pad && effective_mode != CompressionMode::Lossless;
    if do_pad {
        const P: usize = 16;
        let rem = framed.len() % P;
        if rem != 0 { framed.resize(framed.len() + P - rem, 0u8); }
    }
    let padded = do_pad;
    let (pack_data, used_lossless) = match effective_mode {
        CompressionMode::Auto => {
            let packed = aero_pack(&framed)?.data;
            match aero_unpack(&packed) {
                Ok(unpacked) if unpacked == framed => (packed, false),
                _ => (aero_pack_lossless(&framed)?.data, true),
            }
        }
        CompressionMode::Lossless => (aero_pack_lossless(&framed)?.data, true),
        CompressionMode::LosslessPriority => unreachable!(),
    };
    if !opts.recipients.is_empty() {
        let mut pubs = Vec::new();
        for h in &opts.recipients {
            if let Ok(b) = hex::decode(h.trim()) {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    pubs.push(x25519_dalek::PublicKey::from(arr));
                }
            }
        }
        if !pubs.is_empty() {
            let blob = seal2::seal_v2_multi(&pubs, &pack_data, SealMode::Padded)?;
            return Ok(Prepared {
                stream: blob, effective_size, content_hash, data_type, profile,
                cipher: CipherKind::SealV2, has_name, used_lossless, padded,
            });
        }
    }
    if let Some(pk_hex) = &opts.recipient_key {
        if let Ok(pk_bytes) = hex::decode(pk_hex.trim()) {
            if pk_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&pk_bytes);
                let pub_key = x25519_dalek::PublicKey::from(arr);
                let blob = seal2::seal_v2(&pub_key, &pack_data, SealMode::Padded)?;
                return Ok(Prepared {
                    stream: blob, effective_size, content_hash, data_type, profile,
                    cipher: CipherKind::SealV2, has_name, used_lossless, padded,
                });
            }
        }
    }
    let stream = match cipher {
        CipherKind::None => pack_data,
        CipherKind::SealV1 => {
            let mode = if opts.pad { SealMode::Padded } else { SealMode::Plain };
            seal(&opts.password, &pack_data, mode)?
        }
        CipherKind::SealV2 => unreachable!(),
    };
    Ok(Prepared {
        stream, effective_size, content_hash, data_type, profile,
        cipher, has_name, used_lossless, padded,
    })
}

fn load_logo(bytes: &[u8]) -> Option<image::GrayImage> {
    image::load_from_memory(bytes).ok().map(|img| img.to_luma8())
}

fn build_flags(opts: &EncodeOptions, p: &Prepared) -> u8 {
    let mut f = 0u8;
    if p.padded { f |= HEADER_FLAG_PADDED; }
    if p.has_name { f |= HEADER_FLAG_NAMED; }
    if opts.signing_key.is_some() { f |= HEADER_FLAG_SIGNED; }
    if opts.hmac_enabled && (!opts.password.is_empty() || p.cipher == CipherKind::SealV2) {
        f |= HEADER_FLAG_HMAC;
    }
    if opts.gamma { f |= HEADER_FLAG_GAMMA; }
    f
}

fn finalize_header(mut h: AeroHeader, opts: &EncodeOptions) -> Result<AeroHeader> {
    if h.flags & HEADER_FLAG_HMAC != 0 {
        let raw = h.hmac_input();
        let mac = hmac_sha256(opts.password.as_bytes(), &raw);
        h.hmac.copy_from_slice(&mac[..16]);
        h.checksum = h.compute_checksum();
    }
    if let Some(sk) = &opts.signing_key {
        let mut raw = h.to_bytes();
        for b in raw[30..94].iter_mut() { *b = 0; }
        h.signature = sign_header(sk, &raw);
        h.checksum = h.compute_checksum();
    }
    Ok(h)
}

fn encode_glint(
    framed: &[u8],
    opts: &EncodeOptions,
    logo: Option<&image::GrayImage>,
) -> Result<image::GrayImage> {
    let with_fec = crate::fec::encode(framed)?;
    let glint = encode_stream(&with_fec, logo, opts.gamma, opts.mask)?;
    Ok(if opts.border {
        crate::encoder::aeroglint::wrap_with_border(&glint.image)
    } else {
        glint.image
    })
}

pub fn encode_payload(payload: &[u8], opts: &EncodeOptions) -> Result<EncodeOutcome> {
    let p = prepare(payload, opts)?;
    let flags = build_flags(opts, &p);
    let logo = opts.center_logo.as_deref().and_then(load_logo);
    let mut header = AeroHeader::new(
        p.data_type, CompressionKind::AeroPack, p.cipher, flags,
        p.effective_size as u32, p.stream.len() as u32, p.content_hash,
    );
    header.resilience_level = opts.resilience_level;
    header = finalize_header(header, opts)?;
    header.page_crc = fnv32(&p.stream);
    header.checksum = header.compute_checksum();
    let mut framed = Vec::with_capacity(AERO_HEADER_SIZE + p.stream.len());
    framed.extend_from_slice(&header.to_bytes());
    framed.extend_from_slice(&p.stream);
    let image = encode_glint(&framed, opts, logo.as_ref())?;

    let ratio = if !p.stream.is_empty() { payload.len() as f64 / p.stream.len() as f64 } else { 1.0 };
    Ok(EncodeOutcome {
        image,
        payload_bytes: payload.len(),
        compressed_bytes: p.stream.len(),
        data_type: p.data_type,
        cipher: p.cipher,
        content_hash: hex::encode(p.content_hash),
        profile: p.profile,
        ratio,
    })
}

pub fn encode_aeroflow(payload: &[u8], opts: &EncodeOptions) -> Result<FlowOutcome> {
    let p = prepare(payload, opts)?;
    const FEC_SAFE_LIMIT: usize = 600;
    let max_blocks = FEC_SAFE_LIMIT / 255;
    if max_blocks == 0 { return Err(anyhow!("capacity too small")); }
    let max_framed = max_blocks * 223;
    let chunk_data_size = max_framed.saturating_sub(AERO_HEADER_SIZE);
    if chunk_data_size == 0 { return Err(anyhow!("capacity too small")); }

    let level = ResilienceLevel::from_u8(opts.resilience_level);
    let (data_pg, par_pg) = level.split();
    let group_size = data_pg + par_pg;

    let total_chunks_needed = ((p.stream.len() + chunk_data_size - 1) / chunk_data_size).max(1);
    let num_groups = ((total_chunks_needed + data_pg - 1) / data_pg).max(1);
    // When no parity, page count = data chunks needed (no padding to group size).
    // When parity, page count = full groups (200 data + K parity each).
    let total_pages = if par_pg == 0 {
        total_chunks_needed as u16
    } else {
        (num_groups * group_size) as u16
    };
    if total_pages as usize > 65535 { return Err(anyhow!("too many pages: {}", total_pages)); }

    let flags = build_flags(opts, &p) | HEADER_FLAG_MULTIPAGE;
    let logo = opts.center_logo.as_deref().and_then(load_logo);

    let mut frames: Vec<image::GrayImage> = Vec::with_capacity(total_pages as usize);

    for g in 0..num_groups {
        let group_stream_start = g * data_pg * chunk_data_size;
        let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(data_pg);
        // When no parity: last group emits only remaining chunks.
        let is_last = g == num_groups - 1;
        let chunks_this_group = if par_pg == 0 && is_last {
            let remaining = total_chunks_needed - g * data_pg;
            remaining.max(1).min(data_pg)
        } else {
            data_pg
        };
        for i in 0..chunks_this_group {
            let s = group_stream_start + i * chunk_data_size;
            let mut sh = vec![0u8; chunk_data_size];
            if s < p.stream.len() {
                let e = (s + chunk_data_size).min(p.stream.len());
                let n = e - s;
                sh[..n].copy_from_slice(&p.stream[s..e]);
            }
            chunks.push(sh);
        }
        let parity: Vec<Vec<u8>> = if par_pg > 0 {
            crate::resilience::add_parity_n(&chunks, data_pg, par_pg)?
        } else {
            Vec::new()
        };
        // Parallel page encoding (native): rayon speedup ~4x on 8+ cores
        #[cfg(not(target_arch = "wasm32"))]
        {
                        let results: Result<Vec<image::GrayImage>> = (0..chunks.len()).into_par_iter()
                .map(|i| -> Result<image::GrayImage> {
                    let page_idx = (g * group_size + i) as u16;
                    let mut h = AeroHeader::with_page(
                        p.data_type, CompressionKind::AeroPack, p.cipher, flags,
                        p.effective_size as u32, p.stream.len() as u32,
                        page_idx, total_pages, p.content_hash,
                    );
                    h.resilience_level = opts.resilience_level;
                    h = finalize_header(h, opts)?;
                    h.page_crc = fnv32(&chunks[i]);
                    h.checksum = h.compute_checksum();
                    let mut framed = Vec::with_capacity(AERO_HEADER_SIZE + chunk_data_size);
                    framed.extend_from_slice(&h.to_bytes());
                    framed.extend_from_slice(&chunks[i]);
                    encode_glint(&framed, opts, logo.as_ref())
                })
                .collect();
            frames.extend(results?);
        }
        #[cfg(target_arch = "wasm32")]
        {
            for i in 0..chunks.len() {
                let page_idx = (g * group_size + i) as u16;
                let mut h = AeroHeader::with_page(
                    p.data_type, CompressionKind::AeroPack, p.cipher, flags,
                    p.effective_size as u32, p.stream.len() as u32,
                    page_idx, total_pages, p.content_hash,
                );
                h.resilience_level = opts.resilience_level;
                h = finalize_header(h, opts)?;
                h.page_crc = fnv32(&chunks[i]);
                h.checksum = h.compute_checksum();
                let mut framed = Vec::with_capacity(AERO_HEADER_SIZE + chunk_data_size);
                framed.extend_from_slice(&h.to_bytes());
                framed.extend_from_slice(&chunks[i]);
                frames.push(encode_glint(&framed, opts, logo.as_ref())?);
            }
        }
        for i in 0..par_pg {
            let page_idx = (g * group_size + data_pg + i) as u16;
            let mut h = AeroHeader::with_page(
                p.data_type, CompressionKind::AeroPack, p.cipher, flags,
                p.effective_size as u32, p.stream.len() as u32,
                page_idx, total_pages, p.content_hash,
            );
            h.resilience_level = opts.resilience_level;
            h = finalize_header(h, opts)?;
            h.page_crc = fnv32(&parity[i]);
            h.checksum = h.compute_checksum();
            let mut framed = Vec::with_capacity(AERO_HEADER_SIZE + chunk_data_size);
            framed.extend_from_slice(&h.to_bytes());
            framed.extend_from_slice(&parity[i]);
            frames.push(encode_glint(&framed, opts, logo.as_ref())?);
        }
    }

    Ok(FlowOutcome {
        frames,
        page_count: total_pages as usize,
        payload_bytes: payload.len(),
        compressed_bytes: p.stream.len(),
        data_type: p.data_type,
        cipher: p.cipher,
        content_hash: hex::encode(p.content_hash),
        profile: p.profile,
        resilience_level: opts.resilience_level,
        num_groups,
        data_pages_per_group: data_pg,
        parity_pages_per_group: par_pg,
    })
}

fn verify_roundtrip(image: &image::GrayImage, password: &str) -> Result<Vec<u8>> {
    use image::ImageEncoder;
    use image::codecs::png::PngEncoder;
    let (w, h) = (image.width(), image.height());
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(image.as_raw(), w, h, image::ExtendedColorType::L8)
        .map_err(|e| anyhow!("verify png: {}", e))?;
    let dec = crate::decoder::pipeline::decode_from_bytes(&png, password, None)?;
    if !dec.hash_ok {
        return Err(anyhow!("verify: hash mismatch after encode"));
    }
    Ok(dec.payload)
}