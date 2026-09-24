//! Minimal WAV reader/writer. No external deps.
//! Supports PCM 8/16/24/32-bit, mono/stereo/multichannel.

use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct WavFile {
    pub sample_rate: u32,
    pub channels: u16,
    pub bits_per_sample: u16,
    /// Interleaved f32 samples in [-1.0, 1.0]. Length = frames * channels.
    pub samples: Vec<f32>,
}

impl WavFile {
    pub fn frames(&self) -> usize {
        if self.channels == 0 { 0 } else { self.samples.len() / self.channels as usize }
    }
}

pub fn read_wav(data: &[u8]) -> Result<WavFile> {
    if data.len() < 12 { return Err(anyhow!("wav: too short")); }
    if &data[0..4] != b"RIFF" { return Err(anyhow!("wav: not RIFF")); }
    if &data[8..12] != b"WAVE" { return Err(anyhow!("wav: not WAVE")); }
    let mut pos = 12usize;
    let mut fmt: Option<(u16, u16, u32, u16)> = None;
    let mut pcm_data: Option<Vec<u8>> = None;
    while pos + 8 <= data.len() {
        let chunk_id = &data[pos..pos+4];
        let chunk_len = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]) as usize;
        pos += 8;
        if pos + chunk_len > data.len() { break; }
        let chunk = &data[pos..pos+chunk_len];
        if chunk_id == b"fmt " {
            if chunk.len() < 16 { return Err(anyhow!("wav: short fmt")); }
            let af = u16::from_le_bytes([chunk[0], chunk[1]]);
            let ch = u16::from_le_bytes([chunk[2], chunk[3]]);
            let sr = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let bps = u16::from_le_bytes([chunk[14], chunk[15]]);
            fmt = Some((af, ch, sr, bps));
        } else if chunk_id == b"data" {
            pcm_data = Some(chunk.to_vec());
        }
        pos += chunk_len + (chunk_len & 1);
    }
    let (af, channels, sample_rate, bits_per_sample) =
        fmt.ok_or_else(|| anyhow!("wav: no fmt chunk"))?;
    if af != 1 && af != 0xFFFE {
        return Err(anyhow!("wav: unsupported format {} (need PCM)", af));
    }
    if channels == 0 { return Err(anyhow!("wav: zero channels")); }
    let pcm = pcm_data.ok_or_else(|| anyhow!("wav: no data chunk"))?;
    let samples = decode_pcm(&pcm, bits_per_sample)?;
    Ok(WavFile { sample_rate, channels, bits_per_sample, samples })
}

fn decode_pcm(data: &[u8], bps: u16) -> Result<Vec<f32>> {
    let mut out = Vec::with_capacity(data.len() * 8 / bps.max(1) as usize);
    match bps {
        8 => for &b in data { out.push((b as f32 - 128.0) / 128.0); },
        16 => for c in data.chunks_exact(2) {
            let v = i16::from_le_bytes([c[0], c[1]]);
            out.push(v as f32 / 32768.0);
        },
        24 => for c in data.chunks_exact(3) {
            let v = ((c[2] as i32) << 16) | ((c[1] as i32) << 8) | (c[0] as i32);
            let v = if v & 0x800000 != 0 { v - 0x1000000 } else { v };
            out.push(v as f32 / 8388608.0);
        },
        32 => for c in data.chunks_exact(4) {
            let v = i32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            out.push(v as f32 / 2147483648.0);
        },
        _ => return Err(anyhow!("wav: unsupported bps {}", bps)),
    }
    Ok(out)
}

pub fn write_wav(w: &WavFile) -> Result<Vec<u8>> {
    let bytes_per_sample = (w.bits_per_sample / 8) as usize;
    if bytes_per_sample == 0 { return Err(anyhow!("wav: bad bps")); }
    let data_len = w.samples.len() * bytes_per_sample;
    let mut out = Vec::with_capacity(44 + data_len);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&w.channels.to_le_bytes());
    out.extend_from_slice(&w.sample_rate.to_le_bytes());
    let byte_rate = w.sample_rate * w.channels as u32 * bytes_per_sample as u32;
    out.extend_from_slice(&byte_rate.to_le_bytes());
    out.extend_from_slice(&(w.channels * w.bits_per_sample / 8).to_le_bytes());
    out.extend_from_slice(&w.bits_per_sample.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    match w.bits_per_sample {
        8 => for &s in &w.samples {
            out.push(((s * 128.0) + 128.0).clamp(0.0, 255.0) as u8);
        },
        16 => for &s in &w.samples {
            out.extend_from_slice(&((s * 32768.0).clamp(-32768.0, 32767.0) as i16).to_le_bytes());
        },
        24 => for &s in &w.samples {
            let v = (s * 8388608.0).clamp(-8388608.0, 8388607.0) as i32;
            let b = v.to_le_bytes();
            out.extend_from_slice(&b[0..3]);
        },
        32 => for &s in &w.samples {
            out.extend_from_slice(&((s * 2147483648.0).clamp(-2147483648.0, 2147483647.0) as i32).to_le_bytes());
        },
        _ => return Err(anyhow!("wav: unsupported bps {}", w.bits_per_sample)),
    }
    Ok(out)
}