//! APNG writer for multi-page AeroGlint frames.
//!
//! CRITICAL: We preserve the full 0..255 grayscale range.
//! Binarization (from v1 spatial tiles) destroys QPSK amplitude
//! and breaks FEC decoding. Do NOT threshold here.

use anyhow::{anyhow, Result};
use image::GrayImage;
use png::{BitDepth, ColorType, Encoder};
use std::path::Path;

pub fn save_apng(frames: &[GrayImage], out: &Path, fps: u32) -> Result<()> {
    let bytes = write_apng_to_vec(frames, fps)?;
    std::fs::write(out, &bytes)?;
    Ok(())
}

pub fn write_apng_to_vec(frames: &[GrayImage], fps: u32) -> Result<Vec<u8>> {
    if frames.is_empty() { return Err(anyhow!("no frames")); }
    let (w0, h0) = (frames[0].width(), frames[0].height());
    for (i, f) in frames.iter().enumerate() {
        if f.width() != w0 || f.height() != h0 {
            return Err(anyhow!("frame {} size differs", i));
        }
    }
    let fps = if fps == 0 { 5 } else { fps };
    let mut buf = Vec::new();
    {
        let mut e = Encoder::new(&mut buf, w0, h0);
        e.set_color(ColorType::Grayscale);
        e.set_depth(BitDepth::Eight);
        e.set_animated(frames.len() as u32, 0)?;
        let mut w = e.write_header()?;
        let dn = 1u16;
        let dd = fps.min(u16::MAX as u32) as u16;
        for (i, f) in frames.iter().enumerate() {
            // CRITICAL: raw bytes preserved exactly. No thresholding.
            let raw = f.as_raw().clone();
            if i > 0 { w.set_frame_delay(dn, dd)?; }
            w.write_image_data(&raw)?;
        }
        w.finish()?;
    }
    Ok(buf)
}
