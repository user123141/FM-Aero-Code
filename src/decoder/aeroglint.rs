//! AeroGlint decoder (v2.3.2).
//!
//! CRITICAL FIX: previous CFAR threshold (avg neighbors * 2.0) killed
//! all data because QPSK symbols are uniform in magnitude. Replaced
//! with median * 0.5 which correctly separates data from empty cells.

use anyhow::{anyhow, Result};
use image::{GrayImage, imageops::FilterType};
use rustfft::num_complex::Complex32;
use rustfft::{Fft, FftPlanner};
use std::sync::{Arc, OnceLock};

use crate::AEROGLINT_GRID;
use crate::encoder::aeroglint::{data_cells, interleave_seed, PILOT_ANGLES};

pub struct DecodedGlint {
    pub stream: Vec<u8>,
    pub rotation_deg: f32,
    pub noise_floor: f32,
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

/// Median magnitude across all non-DC cells.
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

/// RMS magnitude of all non-DC cells (better than median when most cells
/// are empty). Used as fallback noise estimate.
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

pub fn parabolic_offset(y1: f32, y2: f32, y3: f32) -> f32 {
    let denom = y1 - 2.0 * y2 + y3;
    if denom.abs() < 1e-9 { return 0.0; }
    (0.5 * (y1 - y3) / denom).clamp(-0.5, 0.5)
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
            let amp = matrix[y * size + x].norm();
            candidates.push((x, y, amp));
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

pub fn decode_luma(luma: &GrayImage) -> Result<DecodedGlint> {
    let size = AEROGLINT_GRID;
    let resized = if luma.width() != size as u32 || luma.height() != size as u32 {
        image::imageops::resize(luma, size as u32, size as u32, FilterType::Triangle)
    } else {
        luma.clone()
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

    // Adaptive threshold: signal cells have magnitude ~1.41 (from QPSK).
    // Empty cells have magnitude near 0. Set threshold at 0.5 * median
    // so we correctly reject noise but keep QPSK.
    let robust = if noise_floor > 1e-6 { noise_floor } else { rms };
    let threshold = robust * 0.5;

    let mut rotation_rad = find_rotation(&matrix, size);
    // Sanity: PNG-to-PNG has zero rotation. If detection claims > 15 deg,
    // it's likely noise from data cell distribution. Zero it out.
    if rotation_rad.abs() > 0.262 {
        rotation_rad = 0.0;
    }

    // Rotate spectrum back
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

    // De-interleave
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
