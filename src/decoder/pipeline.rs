use anyhow::{anyhow, Result};
use image::GrayImage;
use std::collections::HashMap;

use crate::crypto::{
    constant_time_eq, content_hash_8, hmac_sha256, sha256_short, verify_header, CipherKind,
};
use crate::decoder::aeroglint::{decode_luma, decode_luma_multipass};
use crate::decoder::apng_reader::load_luma_from_bytes;
use crate::encoder::compressor::aero_unpack;
use crate::encoder::pipeline::strip_filename;
use crate::types::{
    AeroHeader, DataType, ResilienceLevel, AERO_HEADER_SIZE,
    HEADER_FLAG_HMAC, HEADER_FLAG_NAMED, HEADER_FLAG_PADDED, HEADER_FLAG_SIGNED,
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
    pub pages_received: usize,
    pub pages_total: usize,
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

fn finish(header: &AeroHeader, stream: Vec<u8>, password: &str, verify_key: Option<&VerifyingKey>)
    -> Result<(Vec<u8>, String, bool, bool, bool)>
{
    let mut hmac_ok = true;
    if header.flags & HEADER_FLAG_HMAC != 0 && !password.is_empty() {
        let raw = header.hmac_input();
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
        eprintln!("[warn] declared size {} exceeds cap {}", header.original_size, MAX_DECOMPRESSED_BYTES);
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

fn outcome(h: AeroHeader, s: Vec<u8>, pw: &str, vk: Option<&VerifyingKey>, recovered: bool,
           recv: usize, total: usize) -> Result<DecodeOutcome>
{
    let (payload, original_filename, hash_ok, signature_ok, hmac_ok) = finish(&h, s, pw, vk)?;
    let sha = sha256_short(&payload);
    let created = { let s = h.created_at_str(); if s == "unknown" { None } else { Some(s) } };
    Ok(DecodeOutcome {
        payload, header: h, sha256: sha, hash_ok, signature_ok, hmac_ok,
        original_filename, created_at: created,
        recovered_from_parity: recovered,
        pages_received: recv, pages_total: total,
    })
}

pub fn decode_image(img: &GrayImage, password: &str, vk: Option<&VerifyingKey>) -> Result<DecodeOutcome> {
    let stream = recover_stream(img)?;
    let (h, payload) = split_header_and_payload(&stream)?;
    outcome(h, payload, password, vk, false, 1, 1)
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

/// Struct for a decoded page before grouping.
struct Page {
    stream: Vec<u8>,
    header: AeroHeader,
}

fn decode_frames_multi(frames: &[GrayImage], password: &str, _vk: Option<&VerifyingKey>) -> Result<DecodeOutcome> {
    let mut pages: Vec<Page> = Vec::with_capacity(frames.len());
    let mut bad: usize = 0;
    let mut total_pages: u16 = 0;
    let mut resilience_level: u8 = 0;

    for f in frames.iter() {
        let glint = match decode_luma_multipass(f) { Ok(g) => g, Err(_) => { bad += 1; continue; } };
        let stream = match crate::fec::decode(&glint.stream) { Ok(s) => s, Err(_) => { bad += 1; continue; } };
        let header = match AeroHeader::from_bytes(&stream) {
            Some(h) => h,
            None => { bad += 1; continue; }
        };
        // CRC check
        if header.page_crc != 0 {
            let body = &stream[AERO_HEADER_SIZE..];
            if crate::types::fnv32(body) != header.page_crc {
                bad += 1;
                continue;
            }
        }
        if total_pages == 0 { total_pages = header.page_total; resilience_level = header.resilience_level; }
        pages.push(Page { stream, header });
    }

    if pages.is_empty() {
        return Err(anyhow!("no valid pages ({} failed)", bad));
    }

    let level = ResilienceLevel::from_u8(resilience_level);
    let (data_pg, par_pg) = level.split();
    let group_size = data_pg + par_pg;

    let received = pages.len();
    let mut recovered_from_parity = false;

    // Build per-group slot maps
    let num_groups = (total_pages as usize + group_size - 1) / group_size;
    let mut groups: Vec<HashMap<usize, Vec<u8>>> = (0..num_groups)
        .map(|_| HashMap::new()).collect();

    for page in &pages {
        let idx = page.header.page_index as usize;
        let g = idx / group_size;
        let slot = idx % group_size;
        if g < num_groups {
            groups[g].insert(slot, page.stream.clone());
        }
    }

    // Reconstruct data page streams for each group
    let mut all_streams: Vec<(u16, Vec<u8>)> = Vec::with_capacity(total_pages as usize);

    for (g, group) in groups.iter().enumerate() {
        // Compute how many DATA pages this group should contain.
        // When no parity and it is the last group, it may be partial.
        let expected_in_group = if par_pg == 0 {
            let remaining = (total_pages as usize).saturating_sub(g * data_pg);
            remaining.min(data_pg)
        } else {
            data_pg
        };
        let data_present: Vec<usize> = (0..expected_in_group)
            .filter(|i| group.contains_key(i)).collect();
        if data_present.len() == expected_in_group {
            // Direct use (partial group handled correctly)
            for slot in 0..expected_in_group {
                let stream = group.get(&slot).unwrap().clone();
                let idx = (g * group_size + slot) as u16;
                all_streams.push((idx, stream));
            }
        } else if par_pg > 0 {
            // Try parity recovery
            eprintln!("[info] group {}: {} / {} data pages present, attempting RS recovery",
                      g, data_present.len(), data_pg);
            // Extract bodies (chunks) from each present page. Strip header.
            let mut present: Vec<(usize, Vec<u8>)> = Vec::new();
            let mut chunk_size = 0usize;
            let mut template_header: Option<Vec<u8>> = None;
            for (slot, stream) in group.iter() {
                let body = if stream.len() > AERO_HEADER_SIZE {
                    stream[AERO_HEADER_SIZE..].to_vec()
                } else { continue };
                if body.len() > chunk_size { chunk_size = body.len(); }
                if template_header.is_none() {
                    template_header = Some(stream[..AERO_HEADER_SIZE].to_vec());
                }
                present.push((*slot, body));
            }
            if present.is_empty() || template_header.is_none() {
                return Err(anyhow!("group {}: no usable pages", g));
            }
            // Recover chunks
            let recovered = match crate::resilience::recover_group_n(&present, data_pg, par_pg) {
                Ok(r) => r,
                Err(e) => {
                    return Err(anyhow!("recovered {} of {} pages; RS failed on group {}: {}",
                        received, total_pages, g, e));
                }
            };
            recovered_from_parity = true;
            let tmpl = template_header.unwrap();
            for (i, chunk) in recovered.into_iter().enumerate() {
                let idx = (g * group_size + i) as u16;
                // Build synthetic header: use template, patch page_index + page_crc
                let mut stream = tmpl.clone();
                stream[18] = (idx & 0xFF) as u8;
                stream[19] = ((idx >> 8) & 0xFF) as u8;
                // Patch page_crc
                let crc = crate::types::fnv32(&chunk);
                stream[114..118].copy_from_slice(&crc.to_le_bytes());
                // Recompute checksum
                // (truncate chunks to their original size)
                stream.extend_from_slice(&chunk);
                all_streams.push((idx, stream));
            }
        } else {
            return Err(anyhow!("group {}: only {}/{} data pages, no parity", g, data_present.len(), data_pg));
        }
    }

    all_streams.sort_by_key(|(i, _)| *i);
    let streams: Vec<Vec<u8>> = all_streams.into_iter().map(|(_, s)| s).collect();

    // Convert to payload via concat + truncate
    let mut sample_h: Option<AeroHeader> = None;
    let mut combined: Vec<u8> = Vec::new();
    for s in &streams {
        let (h, payload) = match split_header_and_payload(s) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if sample_h.is_none() { sample_h = Some(h.clone()); }
        combined.extend_from_slice(&payload);
    }
    let header = sample_h.ok_or_else(|| anyhow!("no valid headers"))?;
    let declared = header.payload_size as usize;
    if declared > 0 && declared < combined.len() { combined.truncate(declared); }

    outcome(header, combined, password, None, recovered_from_parity, received, total_pages as usize)
}

pub fn peek_header_from_bytes(data: &[u8]) -> Result<AeroHeader> {
    let img = load_luma_from_bytes(data)?;
    let stream = recover_stream(&img)?;
    let (h, _) = split_header_and_payload(&stream)?;
    Ok(h)
}

pub fn finish_from_stream(stream: &[u8], password: &str) -> Result<DecodeOutcome> {
    let (h, payload) = split_header_and_payload(stream)?;
    outcome(h, payload, password, None, false, 1, 1)
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
    if declared > 0 && declared < combined.len() { combined.truncate(declared); }
    outcome(header, combined, password, None, false, streams.len(), streams.len())
}

pub fn try_multi_recipient(
    data: &[u8],
    recipient_secret: &x25519_dalek::StaticSecret,
    recipient_public: &x25519_dalek::PublicKey,
) -> Result<DecodeOutcome> {
    let img = load_luma_from_bytes(data)?;
    let stream = recover_stream(&img)?;
    let (h, _) = split_header_and_payload(&stream)?;
    if h.cipher != CipherKind::SealV2 { return Err(anyhow!("not SealV2")); }
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
    let created = { let s = h.created_at_str(); if s == "unknown" { None } else { Some(s) } };
    Ok(DecodeOutcome {
        payload: up, header: h, sha256: sha, hash_ok,
        signature_ok: true, hmac_ok: true,
        original_filename: fname, created_at: created,
        recovered_from_parity: false, pages_received: 1, pages_total: 1,
    })
}

// Silence unused import warning
#[allow(dead_code)]
fn _use_datatype() -> DataType { DataType::Text }