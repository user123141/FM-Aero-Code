use anyhow::{anyhow, Result};
use image::GrayImage;

use crate::crypto::{
    constant_time_eq, content_hash_8, hmac_sha256, sha256_short, verify_header, CipherKind,
};
use crate::decoder::aeroglint::decode_luma;
use crate::decoder::apng_reader::load_luma_from_bytes;
use crate::encoder::compressor::aero_unpack;
use crate::encoder::pipeline::strip_filename;
use crate::types::{
    AeroHeader, AERO_HEADER_SIZE, HEADER_FLAG_HMAC, HEADER_FLAG_NAMED,
    HEADER_FLAG_PADDED, HEADER_FLAG_SIGNED,
};
use crate::MAX_DECOMPRESSED_BYTES;
use ed25519_dalek::VerifyingKey;

pub struct DecodeOutcome {
    pub payload: Vec<u8>,
    pub header: AeroHeader,
    pub sha256: String,
    pub hash_ok: bool,
    pub signature_ok: bool,
    pub hmac_ok: bool,
    pub original_filename: String,
    pub created_at: Option<String>,
    pub recovered_from_parity: bool,
}

fn recover_stream(luma: &GrayImage) -> Result<Vec<u8>> {
    let glint = decode_luma(luma)?;
    crate::fec::decode(&glint.stream)
}

pub fn split_header_and_payload(stream: &[u8]) -> Result<(AeroHeader, Vec<u8>)> {
    if stream.len() < AERO_HEADER_SIZE {
        return Err(anyhow!("stream too short ({} < {})", stream.len(), AERO_HEADER_SIZE));
    }
    let header = AeroHeader::from_bytes(&stream[..AERO_HEADER_SIZE])
        .ok_or_else(|| anyhow!("bad header"))?;
    let payload_end = AERO_HEADER_SIZE + header.payload_size as usize;
    let payload = if payload_end <= stream.len() {
        stream[AERO_HEADER_SIZE..payload_end].to_vec()
    } else {
        stream[AERO_HEADER_SIZE..].to_vec()
    };
    Ok((header, payload))
}

fn finish(
    header: &AeroHeader,
    stream: Vec<u8>,
    password: &str,
    verify_key: Option<&VerifyingKey>,
) -> Result<(Vec<u8>, String, bool, bool, bool)> {
    let mut hmac_ok = true;
    if header.flags & HEADER_FLAG_HMAC != 0 && !password.is_empty() {
        let mut raw = header.to_bytes();
        for b in raw[94..110].iter_mut() { *b = 0; }
        let mac = hmac_sha256(password.as_bytes(), &raw);
        hmac_ok = constant_time_eq(&mac[..16], &header.hmac);
    }
    let mut signature_ok = true;
    if header.flags & HEADER_FLAG_SIGNED != 0 {
        if let Some(vk) = verify_key {
            let mut raw = header.to_bytes();
            for b in raw[30..94].iter_mut() { *b = 0; }
            signature_ok = verify_header(vk, &raw, &header.signature);
        } else {
            signature_ok = false;
        }
    }
    let decrypted = match header.cipher {
        CipherKind::None => stream,
        CipherKind::SealV1 => {
            if password.is_empty() { return Err(anyhow!("password required")); }
            crate::crypto::seal::open(password, &stream)
                .map_err(|_| anyhow!("wrong password or corrupted"))?
        }
        CipherKind::SealV2 => {
            return Err(anyhow!("SealV2 needs recipient key"));
        }
    };
    if header.original_size as usize > MAX_DECOMPRESSED_BYTES {
        return Err(anyhow!("declared size exceeds cap"));
    }
    let mut up = aero_unpack(&decrypted)?;
    if header.flags & HEADER_FLAG_PADDED != 0 {
        let n = header.original_size as usize;
        if n <= up.len() { up.truncate(n); }
    }
    let mut fname = String::new();
    if header.flags & HEADER_FLAG_NAMED != 0 {
        if let Some((n, body)) = strip_filename(&up) { fname = n; up = body; }
    }
    let hash_ok = constant_time_eq(&content_hash_8(&up), &header.content_hash);
    Ok((up, fname, hash_ok, signature_ok, hmac_ok))
}

fn outcome(h: AeroHeader, s: Vec<u8>, pw: &str, vk: Option<&VerifyingKey>, recovered: bool) -> Result<DecodeOutcome> {
    let (payload, original_filename, hash_ok, signature_ok, hmac_ok) = finish(&h, s, pw, vk)?;
    let sha = sha256_short(&payload);
    let created = {
        let s = h.created_at_str();
        if s == "unknown" { None } else { Some(s) }
    };
    Ok(DecodeOutcome {
        payload, header: h, sha256: sha, hash_ok,
        signature_ok, hmac_ok, original_filename, created_at: created,
        recovered_from_parity: recovered,
    })
}

pub fn decode_image(img: &GrayImage, password: &str, vk: Option<&VerifyingKey>) -> Result<DecodeOutcome> {
    let stream = recover_stream(img)?;
    let (h, payload) = split_header_and_payload(&stream)?;
    outcome(h, payload, password, vk, false)
}

pub fn decode_from_bytes(data: &[u8], password: &str, vk: Option<&VerifyingKey>) -> Result<DecodeOutcome> {
    use crate::decoder::apng_reader::{is_apng_bytes, load_apng_frames_from_bytes, load_luma_from_bytes};
    if is_apng_bytes(data) {
        if let Ok(frames) = load_apng_frames_from_bytes(data) {
            if frames.len() > 1 {
                return decode_frames_multi(&frames, password, vk);
            }
        }
    }
    let img = load_luma_from_bytes(data)?;
    decode_image(&img, password, vk)
}

fn decode_frames_multi(frames: &[GrayImage], password: &str, _vk: Option<&VerifyingKey>) -> Result<DecodeOutcome> {
    let total_frames = frames.len();
    let mut pages: Vec<(u16, Vec<u8>)> = Vec::with_capacity(total_frames);
    let mut sample_header: Option<AeroHeader> = None;
    let mut total_pages: u16 = 0;
    let mut failed: usize = 0;
    let mut bad_pages: Vec<u16> = Vec::new();

    for f in frames.iter() {
        let glint = match decode_luma(f) {
            Ok(g) => g,
            Err(_) => { failed += 1; continue; }
        };
        let stream = match crate::fec::decode(&glint.stream) {
            Ok(s) => s,
            Err(_) => { failed += 1; continue; }
        };
        let h = match AeroHeader::from_bytes(&stream) {
            Some(h) => h,
            None => { failed += 1; continue; }
        };
        if sample_header.is_none() { sample_header = Some(h.clone()); total_pages = h.page_total; }
        if h.page_crc != 0 {
            let body = &stream[AERO_HEADER_SIZE..];
            let actual = crate::types::fnv32(body);
            if actual != h.page_crc {
                bad_pages.push(h.page_index);
                failed += 1;
                continue;
            }
        }
        pages.push((h.page_index, stream));
    }

    if pages.is_empty() {
        return Err(anyhow!("no valid pages in {} frames ({} failed)", total_frames, failed));
    }
    if !bad_pages.is_empty() {
        let show = bad_pages.len().min(20);
        let list: Vec<String> = bad_pages[..show].iter().map(|i| i.to_string()).collect();
        eprintln!("[warn] {} of {} pages failed CRC32; {} OK; first bad: {}",
                  bad_pages.len(), total_frames, pages.len(), list.join(","));
    }

    // Detect resilience mode: 250 total pages (200 data + 50 parity)
    let resilience_mode = total_pages == (crate::resilience::DATA_PAGES + crate::resilience::PARITY_PAGES) as u16;

    let mut recovered_from_parity = false;

    if resilience_mode {
        // Try direct: need all 200 data pages present
        let data_present: Vec<(u16, Vec<u8>)> = pages.iter()
            .filter(|(idx, _)| (*idx as usize) < crate::resilience::DATA_PAGES)
            .cloned().collect();

        if data_present.len() == crate::resilience::DATA_PAGES {
            let mut sorted = data_present;
            sorted.sort_by_key(|(i, _)| *i);
            let streams: Vec<Vec<u8>> = sorted.into_iter().map(|(_, s)| s).collect();
            return decode_apng_streams(&streams, password);
        }

        // Need recovery
        eprintln!("[info] resilience recovery: {} data + {} parity present; calling RS",
                  data_present.len(), pages.len() - data_present.len());
        match recover_with_parity(&pages, total_pages) {
            Ok(streams) => {
                recovered_from_parity = true;
                let mut result = decode_apng_streams(&streams, password)?;
                result.recovered_from_parity = true;
                return Ok(result);
            }
            Err(e) => {
                return Err(anyhow!("recovered {}/{} pages; parity recovery failed: {}",
                    pages.len(), total_pages, e));
            }
        }
    }

    // Non-resilience mode: strict
    if total_pages > 0 && (pages.len() as u16) < total_pages {
        let pct = 100.0 * pages.len() as f64 / total_pages as f64;
        return Err(anyhow!("recovered {} of {} pages ({:.1}%)", pages.len(), total_pages, pct));
    }
    pages.sort_by_key(|(i, _)| *i);
    let streams: Vec<Vec<u8>> = pages.into_iter().map(|(_, s)| s).collect();
    decode_apng_streams(&streams, password)
}

fn recover_with_parity(present: &[(u16, Vec<u8>)], _total: u16) -> Result<Vec<Vec<u8>>> {
    use crate::resilience::{DATA_PAGES, PARITY_PAGES, GROUP_SIZE};
    if DATA_PAGES + PARITY_PAGES != GROUP_SIZE {
        return Err(anyhow!("resilience constants mismatch"));
    }
    // Extract body from each stream (skip header)
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; GROUP_SIZE];
    let mut max_body = 0usize;
    for (idx, stream) in present {
        let i = *idx as usize;
        if i >= GROUP_SIZE { continue; }
        let body = if stream.len() > AERO_HEADER_SIZE {
            stream[AERO_HEADER_SIZE..].to_vec()
        } else { continue };
        if body.len() > max_body { max_body = body.len(); }
        slots[i] = Some(body);
    }
    if max_body == 0 { return Err(anyhow!("no bodies")); }

    // Pad all bodies to max_body
    let present_pairs: Vec<(usize, Vec<u8>)> = slots.iter().enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|b| {
            let mut padded = vec![0u8; max_body];
            padded[..b.len()].copy_from_slice(b);
            (i, padded)
        }))
        .collect();

    let recovered_bodies = crate::resilience::recover_group(&present_pairs)?;

    // Rebuild streams with a template header from any present data page
    let template_header = present.iter()
        .find(|(idx, _)| (*idx as usize) < DATA_PAGES)
        .map(|(_, s)| s[..AERO_HEADER_SIZE].to_vec())
        .ok_or_else(|| anyhow!("no data page present to use as header template"))?;

    let mut streams: Vec<Vec<u8>> = Vec::with_capacity(DATA_PAGES);
    for (i, body) in recovered_bodies.iter().enumerate() {
        // Try to preserve original header if we had it, else use template
        let mut stream = if let Some(Some(orig)) = slots.get(i) {
            let mut v = vec![0u8; AERO_HEADER_SIZE];
            v.copy_from_slice(&template_header);
            // Fix page_index in header
            v[18] = (i & 0xFF) as u8;
            v[19] = ((i >> 8) & 0xFF) as u8;
            let _ = orig;
            v
        } else {
            let mut v = vec![0u8; AERO_HEADER_SIZE];
            v.copy_from_slice(&template_header);
            v[18] = (i & 0xFF) as u8;
            v[19] = ((i >> 8) & 0xFF) as u8;
            v
        };
        // Trim body to original chunk size (header.payload_size - offset)
        stream.extend_from_slice(body);
        streams.push(stream);
    }
    Ok(streams)
}

pub fn peek_header_from_bytes(data: &[u8]) -> Result<AeroHeader> {
    let img = load_luma_from_bytes(data)?;
    let stream = recover_stream(&img)?;
    let (h, _) = split_header_and_payload(&stream)?;
    Ok(h)
}

pub fn finish_from_stream(stream: &[u8], password: &str) -> Result<DecodeOutcome> {
    let (h, payload) = split_header_and_payload(stream)?;
    outcome(h, payload, password, None, false)
}

pub fn decode_apng_streams(streams: &[Vec<u8>], password: &str) -> Result<DecodeOutcome> {
    if streams.is_empty() { return Err(anyhow!("no streams")); }
    let mut sample: Option<AeroHeader> = None;
    let mut pages: Vec<(u16, Vec<u8>)> = Vec::new();
    for s in streams {
        let (h, payload) = split_header_and_payload(s)?;
        if sample.is_none() { sample = Some(h.clone()); }
        pages.push((h.page_index, payload));
    }
    pages.sort_by_key(|(i, _)| *i);
    let mut combined: Vec<u8> = Vec::new();
    for (_, p) in pages { combined.extend_from_slice(&p); }
    let header = sample.unwrap();
    let declared = header.payload_size as usize;
    if declared > 0 {
        if combined.len() < declared {
            return Err(anyhow!("incomplete stream: {} of {} bytes", combined.len(), declared));
        }
        combined.truncate(declared);
    }
    outcome(header, combined, password, None, false)
}

pub fn try_multi_recipient(
    data: &[u8],
    recipient_secret: &x25519_dalek::StaticSecret,
    recipient_public: &x25519_dalek::PublicKey,
) -> Result<DecodeOutcome> {
    let img = load_luma_from_bytes(data)?;
    let stream = recover_stream(&img)?;
    let (h, _) = split_header_and_payload(&stream)?;
    if h.cipher != CipherKind::SealV2 {
        return Err(anyhow!("not a SealV2 pattern"));
    }
    let decrypted = crate::crypto::seal2::open_v2_multi(
        recipient_secret, recipient_public, &stream[AERO_HEADER_SIZE..],
    ).map_err(|e| anyhow!("multi-open: {}", e))?;
    let mut up = aero_unpack(&decrypted)?;
    if h.flags & HEADER_FLAG_PADDED != 0 {
        let n = h.original_size as usize;
        if n <= up.len() { up.truncate(n); }
    }
    let mut fname = String::new();
    if h.flags & HEADER_FLAG_NAMED != 0 {
        if let Some((n, body)) = strip_filename(&up) { fname = n; up = body; }
    }
    let hash_ok = constant_time_eq(&content_hash_8(&up), &h.content_hash);
    let sha = sha256_short(&up);
    let created = {
        let s = h.created_at_str();
        if s == "unknown" { None } else { Some(s) }
    };
    Ok(DecodeOutcome {
        payload: up, header: h, sha256: sha, hash_ok,
        signature_ok: true, hmac_ok: true,
        original_filename: fname, created_at: created,
        recovered_from_parity: false,
    })
}