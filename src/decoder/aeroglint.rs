//! AeroGlint decoder (v3.0).
//!
//! Adds: gamma inverse, Sauvola adaptive threshold (pre-FFT), border strip.

use anyhow::{anyhow, Result};
use image::{GrayImage, imageops::FilterType};
use rustfft::num_complex::Complex32;
use rustfft::{Fft, FftPlanner};
use std::sync::{Arc, OnceLock};

use crate::AEROGLINT_GRID;
use crate::encoder::aeroglint::{data_cells, interleave_seed, PILOT_ANGLES};

pub const BORDER_PX: u32 = 24;
pub const BORDERED_GRID: u32 = 128 + 2 * BORDER_PX;

pub struct DecodedGlint {
    pub stream: Vec<u8>,
    pub rotation_deg: f32,
    pub noise_floor: f32,
}

static FFT128_FWD: OnceLock<Arc<dyn Fft<f32>>> = OnceLock::new();

fn fft_forward_for(size: usize) -> Arc<dyn Fft<f32>> {
    if size == AEROGLINT_GRID {
        FFT128_FWD.get_or_init(|| {
            let mut p = FftPlanner::new();
            p.plan_fft_forward(AEROGLINT_GRID)
        }).clone()
    } else {
        let mut p = FftPlanner::new();
        p.plan_fft_forward(size)
    }
}

struct SplitMix64 { state: u64 }
impl SplitMix64 {
    fn new(seed: u64) -> Self { Self { state: seed } }
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

fn fft2d(matrix: &mut [Complex32], size: usize) {
    let fft = fft_forward_for(size);
    for y in 0..size {
        fft.process(&mut matrix[y * size..(y + 1) * size]);
    }
    let mut col = vec![Complex32::new(0.0, 0.0); size];
    for x in 0..size {
        for y in 0..size { col[y] = matrix[y * size + x]; }
        fft.process(&mut col);
        for y in 0..size { matrix[y * size + x] = col[y]; }
    }
}

/// Apply inverse gamma: value^2.2.
pub fn undo_gamma(img: &mut GrayImage) {
    let gamma = 2.2f32;
    for p in img.pixels_mut() {
        let v = p.0[0] as f32 / 255.0;
        let corrected = v.powf(gamma);
        p.0[0] = (corrected * 255.0).clamp(0.0, 255.0) as u8;
    }
}

/// Sauvola adaptive threshold. Window w, k=0.34.
/// Result: binary 0 or 255.
pub fn sauvola_threshold(img: &GrayImage, w: u32, k: f32) -> GrayImage {
    let width = img.width();
    let height = img.height();
    if width < w || height < w { return img.clone(); }
    let r = (w / 2) as i32;
    // Precompute integral image and squared
    let mut integral = vec![0u64; ((width + 1) * (height + 1)) as usize];
    let mut integral_sq = vec![0u64; ((width + 1) * (height + 1)) as usize];
    for y in 0..height {
        let mut row_sum: u64 = 0;
        let mut row_sum_sq: u64 = 0;
        for x in 0..width {
            let v = img.get_pixel(x, y).0[0] as u64;
            row_sum += v;
            row_sum_sq += v * v;
            integral[((y + 1) * (width + 1) + (x + 1)) as usize] =
                integral[(y * (width + 1) + (x + 1)) as usize] + row_sum;
            integral_sq[((y + 1) * (width + 1) + (x + 1)) as usize] =
                integral_sq[(y * (width + 1) + (x + 1)) as usize] + row_sum_sq;
        }
    }
    let mut out = GrayImage::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let x0 = (x as i32 - r).max(0) as u32;
            let y0 = (y as i32 - r).max(0) as u32;
            let x1 = (x as i32 + r).min(width as i32 - 1) as u32;
            let y1 = (y as i32 + r).min(height as i32 - 1) as u32;
            let area = ((x1 - x0 + 1) * (y1 - y0 + 1)) as f32;
            let sum = integral[((y1 + 1) * (width + 1) + (x1 + 1)) as usize]
                + integral[(y0 * (width + 1) + x0) as usize]
                - integral[(y0 * (width + 1) + (x1 + 1)) as usize]
                - integral[((y1 + 1) * (width + 1) + x0) as usize];
            let sum_sq = integral_sq[((y1 + 1) * (width + 1) + (x1 + 1)) as usize]
                + integral_sq[(y0 * (width + 1) + x0) as usize]
                - integral_sq[(y0 * (width + 1) + (x1 + 1)) as usize]
                - integral_sq[((y1 + 1) * (width + 1) + x0) as usize];
            let mean = sum as f32 / area;
            let var = (sum_sq as f32 / area) - mean * mean;
            let std = var.max(0.0).sqrt();
            let threshold = mean * (1.0 + k * (std / 128.0 - 1.0));
            let v = img.get_pixel(x, y).0[0] as f32;
            out.put_pixel(x, y, image::Luma([if v > threshold { 255 } else { 0 }]));
        }
    }
    out
}

fn median_amplitude(matrix: &[Complex32], size: usize) -> f32 {
    let c = size / 2;
    let mut amps: Vec<f32> = Vec::with_capacity(size * size);
    for y in 0..size {
        for x in 0..size {
            let dx = (x as i32 - c as i32).abs();
            let dy = (y as i32 - c as i32).abs();
            if dx + dy < 4 { continue; }
            amps.push(matrix[y * size + x].norm());
        }
    }
    if amps.is_empty() { return 0.0; }
    amps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    amps[amps.len() / 2]
}

fn rms_amplitude(matrix: &[Complex32], size: usize) -> f32 {
    let c = size / 2;
    let mut sum = 0.0f64;
    let mut count = 0usize;
    for y in 0..size {
        for x in 0..size {
            let dx = (x as i32 - c as i32).abs();
            let dy = (y as i32 - c as i32).abs();
            if dx + dy < 4 { continue; }
            let m = matrix[y * size + x].norm() as f64;
            sum += m * m;
            count += 1;
        }
    }
    if count == 0 { return 0.0; }
    (sum / count as f64).sqrt() as f32
}

fn find_rotation(matrix: &[Complex32], size: usize) -> f32 {
    let c = size as f32 / 2.0;
    let pilot_r = crate::encoder::aeroglint::PILOT_RADIUS_NORM * c;
    let pilot_r_sq = pilot_r * pilot_r;
    let band: f32 = (c * 0.20).powi(2);
    let mut candidates: Vec<(usize, usize, f32)> = Vec::new();
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            let r2 = dx * dx + dy * dy;
            if (r2 - pilot_r_sq).abs() > band { continue; }
            candidates.push((x, y, matrix[y * size + x].norm()));
        }
    }
    candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let mut peaks: Vec<(usize, usize, f32)> = Vec::new();
    for cand in candidates {
        let mut ok = true;
        for p in &peaks {
            let dx = cand.0 as i32 - p.0 as i32;
            let dy = cand.1 as i32 - p.1 as i32;
            if dx * dx + dy * dy < 25 { ok = false; break; }
        }
        if ok { peaks.push(cand); }
        if peaks.len() >= 4 { break; }
    }
    if peaks.len() < 2 { return 0.0; }
    let mut expected_angles: Vec<f32> = Vec::new();
    for a in PILOT_ANGLES.iter() {
        expected_angles.push(*a);
        expected_angles.push(*a + std::f32::consts::PI);
    }
    let mut deltas: Vec<f32> = Vec::new();
    for &(px, py, _amp) in &peaks {
        let dx = px as f32 - c;
        let dy = py as f32 - c;
        let recv_angle = dy.atan2(dx);
        let mut best_delta = 0.0f32;
        let mut best_err = f32::INFINITY;
        for &ea in &expected_angles {
            let mut d = recv_angle - ea;
            while d > std::f32::consts::PI { d -= std::f32::consts::TAU; }
            while d < -std::f32::consts::PI { d += std::f32::consts::TAU; }
            if d.abs() < best_err { best_err = d.abs(); best_delta = d; }
        }
        deltas.push(best_delta);
    }
    deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    deltas[deltas.len() / 2]
}

/// Strip border if present.
fn strip_border(img: &GrayImage) -> GrayImage {
    if img.width() == BORDERED_GRID && img.height() == BORDERED_GRID {
        return image::imageops::crop_imm(img, BORDER_PX, BORDER_PX, 128, 128).to_image();
    }
    img.clone()
}

pub fn decode_luma(luma: &GrayImage) -> Result<DecodedGlint> {
    decode_luma_opts(luma, false)
}

pub fn decode_luma_opts(luma: &GrayImage, apply_sauvola: bool) -> Result<DecodedGlint> {
    let size = AEROGLINT_GRID;
    let stripped = strip_border(luma);
    let pre_processed = if apply_sauvola {
        sauvola_threshold(&stripped, 15, 0.34)
    } else {
        stripped
    };
    let resized = if pre_processed.width() != size as u32 || pre_processed.height() != size as u32 {
        image::imageops::resize(&pre_processed, size as u32, size as u32, FilterType::Triangle)
    } else {
        pre_processed
    };
    let mut sum = 0.0f64;
    for p in resized.pixels() { sum += p.0[0] as f64; }
    let mean = (sum / (size * size) as f64) as f32;
    let mut matrix: Vec<Complex32> = resized.pixels()
        .map(|p| Complex32::new(p.0[0] as f32 - mean, 0.0))
        .collect();
    fft2d(&mut matrix, size);
    let noise_floor = median_amplitude(&matrix, size);
    let rms = rms_amplitude(&matrix, size);
    let robust = if noise_floor > 1e-6 { noise_floor } else { rms };
    let threshold = robust * 0.5;
    let mut rotation_rad = find_rotation(&matrix, size);
    if rotation_rad.abs() > 0.262 {
        rotation_rad = 0.0;
    }
    let mut compensated = vec![Complex32::new(0.0, 0.0); size * size];
    let c = size as f32 / 2.0;
    let cos_r = (-rotation_rad).cos();
    let sin_r = (-rotation_rad).sin();
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            let sx = (c + dx * cos_r - dy * sin_r).round() as isize;
            let sy = (c + dx * sin_r + dy * cos_r).round() as isize;
            if sx >= 0 && sx < size as isize && sy >= 0 && sy < size as isize {
                compensated[y * size + x] = matrix[sy as usize * size + sx as usize];
            }
        }
    }
    let cells = data_cells(size);
    let mut raw_bits: Vec<u8> = Vec::with_capacity(cells.len() * 2);
    for &(x, y) in &cells {
        let v = compensated[y * size + x];
        let amp = v.norm();
        if amp < threshold {
            raw_bits.push(0);
            raw_bits.push(0);
        } else {
            raw_bits.push(if v.re > 0.0 { 1 } else { 0 });
            raw_bits.push(if v.im > 0.0 { 1 } else { 0 });
        }
    }
    let mut perm: Vec<usize> = (0..cells.len() * 2).collect();
    let mut rng = SplitMix64::new(interleave_seed());
    for i in (1..perm.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        perm.swap(i, j);
    }
    let mut bits: Vec<u8> = vec![0u8; raw_bits.len()];
    for k in 0..perm.len() {
        if k < bits.len() && perm[k] < raw_bits.len() {
            bits[perm[k]] = raw_bits[k];
        }
    }
    if bits.len() < 16 { return Err(anyhow!("not enough subcarriers")); }
    let mut out = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 { break; }
        let mut b = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            b |= bit << (7 - i);
        }
        out.push(b);
    }
    Ok(DecodedGlint {
        stream: out,
        rotation_deg: rotation_rad.to_degrees(),
        noise_floor: threshold,
    })
}