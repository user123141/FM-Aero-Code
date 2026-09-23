//! APNG reader for FM Aero Code 2.
//!
//! IMPORTANT: Unlike v1 (spatial tiles), v2 (AeroGlint spectral) needs the
//! FULL grayscale range preserved. Do NOT binarize. Any threshold here
//! destroys the QPSK amplitude information.

use anyhow::{anyhow, Result};
use image::{GrayImage, Luma};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

const MAX_FRAMES: usize = 65535;

pub fn is_apng(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false; };
    let mut buf = [0u8; 4096];
    let Ok(n) = f.read(&mut buf) else { return false; };
    is_apng_bytes(&buf[..n])
}

pub fn is_apng_bytes(data: &[u8]) -> bool {
    if data.len() < 8 { return false; }
    if &data[0..8] != &[0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A] { return false; }
    data.windows(4).any(|w| w == b"acTL")
}

/// Convert raw PNG bytes to luma, PRESERVING grayscale range.
fn to_luma_preserve(raw: &[u8], w: u32, h: u32, ct: png::ColorType) -> Result<GrayImage> {
    match ct {
        png::ColorType::Grayscale => {
            GrayImage::from_raw(w, h, raw.to_vec()).ok_or_else(|| anyhow!("grayscale alloc"))
        }
        png::ColorType::GrayscaleAlpha => {
            let mut o = Vec::with_capacity((w as usize) * (h as usize));
            for px in raw.chunks_exact(2) { o.push(px[0]); }
            GrayImage::from_raw(w, h, o).ok_or_else(|| anyhow!("grayscale-alpha"))
        }
        png::ColorType::Rgb => {
            let mut o = Vec::with_capacity((w as usize) * (h as usize));
            for px in raw.chunks_exact(3) {
                o.push(((px[0] as u32 * 30 + px[1] as u32 * 59 + px[2] as u32 * 11) / 100) as u8);
            }
            GrayImage::from_raw(w, h, o).ok_or_else(|| anyhow!("rgb"))
        }
        png::ColorType::Rgba => {
            let mut o = Vec::with_capacity((w as usize) * (h as usize));
            for px in raw.chunks_exact(4) {
                o.push(((px[0] as u32 * 30 + px[1] as u32 * 59 + px[2] as u32 * 11) / 100) as u8);
            }
            GrayImage::from_raw(w, h, o).ok_or_else(|| anyhow!("rgba"))
        }
        png::ColorType::Indexed => {
            let mut o = vec![0u8; (w as usize) * (h as usize)];
            let n = o.len().min(raw.len());
            o[..n].copy_from_slice(&raw[..n]);
            GrayImage::from_raw(w, h, o).ok_or_else(|| anyhow!("indexed"))
        }
    }
}

fn decode_frames<R: Read>(reader: R) -> Result<Vec<GrayImage>> {
    let dec = png::Decoder::new(reader);
    let mut r = dec.read_info().map_err(|e| anyhow!("png info: {}", e))?;
    let mut frames = Vec::new();
    let mut last_err: Option<String> = None;
    loop {
        let mut buf = vec![0u8; r.output_buffer_size()];
        match r.next_frame(&mut buf) {
            Ok(info) => {
                let raw = &buf[..info.buffer_size()];
                // CRITICAL: preserve grayscale. Do not threshold.
                let luma = to_luma_preserve(raw, info.width, info.height, info.color_type)?;
                frames.push(luma);
                if frames.len() >= MAX_FRAMES { break; }
            }
            Err(e) => { last_err = Some(format!("{}", e)); break; }
        }
    }
    if frames.is_empty() {
        return Err(anyhow!("no frames ({})", last_err.unwrap_or_else(|| "?".into())));
    }
    Ok(frames)
}

pub fn load_apng_frames(path: &Path) -> Result<Vec<GrayImage>> {
    let file = File::open(path).map_err(|e| anyhow!("open: {}", e))?;
    decode_frames(file)
}

pub fn load_apng_frames_from_bytes(data: &[u8]) -> Result<Vec<GrayImage>> {
    decode_frames(Cursor::new(data))
}

/// Load a single grayscale frame, preserving the full 0..255 range.
pub fn load_grayscale_from_bytes(data: &[u8]) -> Result<GrayImage> {
    // PNG path (single frame or first frame of APNG)
    if data.starts_with(&[0x89,0x50,0x4E,0x47]) {
        if let Ok(frames) = load_apng_frames_from_bytes(data) {
            if !frames.is_empty() { return Ok(frames.into_iter().next().unwrap()); }
        }
    }
    // Fallback for jpeg/bmp via image crate
    let img = image::load_from_memory(data).map_err(|e| anyhow!("decode: {}", e))?;
    Ok(img.to_luma8())
}

/// Legacy alias for compatibility; calls load_grayscale_from_bytes.
pub fn load_luma_from_bytes(data: &[u8]) -> Result<GrayImage> {
    load_grayscale_from_bytes(data)
}

#[allow(dead_code)]
fn _unused_luma_placeholder() -> Luma<u8> { Luma([0u8]) }