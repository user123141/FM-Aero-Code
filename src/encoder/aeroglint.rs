//! AeroGlint encoder (v3.6.0).
//!
//! Photo lives in LOW frequencies only (r < GUARD_INNER). No spatial overlay
//! because sharp edges create broadband FFT ringing that corrupts data cells.

use anyhow::{anyhow, Result};
use image::{GrayImage, Luma, imageops::FilterType};
use rustfft::num_complex::Complex32;
use rustfft::FftPlanner;

use crate::AEROGLINT_GRID;

pub const GUARD_INNER: f32 = 0.22;
pub const GUARD_OUTER: f32 = 0.85;
pub const PILOT_RADIUS_NORM: f32 = 0.50;

// Kept for API compat, unused.
pub const LOGO_SIZE: u32 = 0;

pub const PILOT_ANGLES: [f32; 4] = [
    std::f32::consts::PI / 6.0,
    std::f32::consts::PI / 3.0,
    2.0 * std::f32::consts::PI / 3.0,
    5.0 * std::f32::consts::PI / 6.0,
];

pub const PILOT_VALUES: [Complex32; 4] = [
    Complex32::new(4.0, 0.0),
    Complex32::new(3.5, 0.0),
    Complex32::new(3.0, 0.0),
    Complex32::new(2.5, 0.0),
];

pub const BORDER_FRAME: u32 = 3;
pub const BORDER_PAD: u32 = 7;
pub const BORDER_PX: u32 = BORDER_FRAME + BORDER_PAD;

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

pub fn logo_bounds(_size: usize) -> (usize, usize, usize, usize) {
    (0, 0, 0, 0)
}

pub fn pilot_positions(size: usize) -> [(usize, usize); 4] {
    let c = size as f32 / 2.0;
    let r = PILOT_RADIUS_NORM * c;
    let mut out = [(0usize, 0usize); 4];
    for i in 0..4 {
        let theta = PILOT_ANGLES[i];
        let xf = c + r * theta.cos();
        let yf = c + r * theta.sin();
        let x = (xf.round() as isize).rem_euclid(size as isize) as usize;
        let y = (yf.round() as isize).rem_euclid(size as isize) as usize;
        out[i] = (x, y);
    }
    out
}

pub fn data_cells(size: usize) -> Vec<(usize, usize)> {
    let half = size / 2;
    let pilots = pilot_positions(size);
    let pilot_exclude = 12i32;
    let mut out = Vec::new();
    for y in 0..size {
        for x in 0..size {
            let (mx, my) = ((size - x) % size, (size - y) % size);
            if x == mx && y == my { continue; }
            if (x > mx) || (x == mx && y > my) { continue; }
            let mut skip = false;
            for &(px, py) in &pilots {
                let dx = x as i32 - px as i32;
                let dy = y as i32 - py as i32;
                if dx * dx + dy * dy <= pilot_exclude * pilot_exclude { skip = true; break; }
                let pmx = (size - px) % size;
                let pmy = (size - py) % size;
                let dmx = x as i32 - pmx as i32;
                let dmy = y as i32 - pmy as i32;
                if dmx * dmx + dmy * dmy <= pilot_exclude * pilot_exclude { skip = true; break; }
            }
            if skip { continue; }
            let fx = if x < half { x as f32 } else { x as f32 - size as f32 };
            let fy = if y < half { y as f32 } else { y as f32 - size as f32 };
            let r = (fx * fx + fy * fy).sqrt() / half as f32;
            if r < GUARD_INNER || r > GUARD_OUTER { continue; }
            out.push((x, y));
        }
    }
    out
}

pub fn usable_capacity() -> usize { data_cells(AEROGLINT_GRID).len() * 2 / 8 }

pub struct EncodedGlint {
    pub image: GrayImage,
    pub bytes_used: usize,
    pub capacity_bytes: usize,
}

pub fn interleave_seed() -> u64 { 0x464D2D41_45524F32u64 }

fn set_hermitian(matrix: &mut [Complex32], size: usize, x: usize, y: usize, v: Complex32) {
    matrix[y * size + x] = v;
    let mx = (size - x) % size;
    let my = (size - y) % size;
    matrix[my * size + mx] = v.conj();
}

fn fft2d(matrix: &mut [Complex32], size: usize, inverse: bool) {
    let mut planner = FftPlanner::<f32>::new();
    let fft = if inverse { planner.plan_fft_inverse(size) } else { planner.plan_fft_forward(size) };
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

/// Spectral background: photo spectrum in low-freq band only.
/// Scaled to RMS=1.5 in spatial domain so data cells (at RMS ~0.4)
/// are not overwhelmed by bleed.
fn build_photo_spectrum(size: usize, photo: &GrayImage) -> Vec<Complex32> {
    let resized = image::imageops::resize(photo, size as u32, size as u32, FilterType::Lanczos3);
    let n = (size * size) as f32;
    let mut sum = 0.0f32;
    for p in resized.pixels() { sum += p.0[0] as f32; }
    let mean = sum / n;
    let mut m: Vec<Complex32> = resized.pixels()
        .map(|p| Complex32::new(p.0[0] as f32 - mean, 0.0))
        .collect();
    fft2d(&mut m, size, false);

    let c = size as f32 / 2.0;
    let inner_r_sq = (GUARD_INNER * c) * (GUARD_INNER * c);
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            if dx * dx + dy * dy >= inner_r_sq {
                m[y * size + x] = Complex32::new(0.0, 0.0);
            }
        }
    }

    let mut energy: f64 = 0.0;
    for v in &m { let a = v.norm() as f64; energy += a * a; }
    let n_f = size as f64;
    // Lower target: RMS=1.5 (was 3.0). Keeps data cells dominant.
    let target_energy = (1.5 * n_f) * (1.5 * n_f);
    let scale = ((target_energy / energy.max(1e-6)).sqrt()) as f32;
    for v in m.iter_mut() { *v = *v * scale; }
    m
}

pub fn wrap_with_border(inner: &GrayImage) -> GrayImage {
    let w = inner.width();
    let h = inner.height();
    let total = w + 2 * BORDER_PX;
    let mut out = GrayImage::new(total, total);
    for p in out.pixels_mut() { p.0[0] = 255; }
    for x in 0..total {
        for y in 0..total {
            if x < BORDER_FRAME || y < BORDER_FRAME
                || x >= total - BORDER_FRAME || y >= total - BORDER_FRAME {
                out.put_pixel(x, y, Luma([0]));
            }
        }
    }
    for i in 0..(w + 2) {
        let px = BORDER_PX - 1 + i;
        let py = BORDER_PX - 1 + i;
        if px < total {
            out.put_pixel(px, BORDER_PX - 1, Luma([0]));
            out.put_pixel(px, BORDER_PX + h, Luma([0]));
        }
        if py < total {
            out.put_pixel(BORDER_PX - 1, py, Luma([0]));
            out.put_pixel(BORDER_PX + w, py, Luma([0]));
        }
    }
    for y in 0..h {
        for x in 0..w {
            let p = inner.get_pixel(x, y);
            out.put_pixel(x + BORDER_PX, y + BORDER_PX, *p);
        }
    }
    out
}

pub fn encode_stream(
    stream: &[u8],
    photo: Option<&GrayImage>,
    _gamma: bool,
    _mask: bool,
) -> Result<EncodedGlint> {
    let size = AEROGLINT_GRID;
    let cells = data_cells(size);
    let capacity_bytes = cells.len() * 2 / 8;
    if stream.len() > capacity_bytes {
        return Err(anyhow!("stream {} > glint capacity {}", stream.len(), capacity_bytes));
    }
    let mut matrix = vec![Complex32::new(0.0, 0.0); size * size];

    // 1. Pilots
    let pilots = pilot_positions(size);
    for i in 0..4 {
        let (px, py) = pilots[i];
        set_hermitian(&mut matrix, size, px, py, PILOT_VALUES[i]);
    }

    // 2. Spectral photo background (low-freq only, no spatial overlay)
    if let Some(p) = photo {
        let ps = build_photo_spectrum(size, p);
        for y in 0..size {
            for x in 0..size {
                let v = ps[y * size + x];
                if v.norm() > 0.0 {
                    set_hermitian(&mut matrix, size, x, y, v);
                }
            }
        }
    }

    // 3. QPSK data
    let total_bits = stream.len() * 8;
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for i in 0..total_bits {
        let byte_i = i / 8;
        let bit_hi = 7 - (i % 8);
        bits.push((stream[byte_i] >> bit_hi) & 1);
    }
    let mut perm: Vec<usize> = (0..cells.len() * 2).collect();
    let mut rng = SplitMix64::new(interleave_seed());
    for i in (1..perm.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        perm.swap(i, j);
    }
    for (cell_idx, &(x, y)) in cells.iter().enumerate() {
        let bit_a = cell_idx * 2;
        let bit_b = cell_idx * 2 + 1;
        if bit_b >= perm.len() { break; }
        let src_a = perm[bit_a];
        let src_b = perm[bit_b];
        if src_a >= bits.len() && src_b >= bits.len() { continue; }
        let b1 = if src_a < bits.len() { bits[src_a] } else { 0 };
        let b2 = if src_b < bits.len() { bits[src_b] } else { 0 };
        let re = if b1 == 1 { 1.0 } else { -1.0 };
        let im = if b2 == 1 { 1.0 } else { -1.0 };
        set_hermitian(&mut matrix, size, x, y, Complex32::new(re, im));
    }

    // 4. IFFT
    fft2d(&mut matrix, size, true);

    // 5. Normalize
    let mut mn = f32::INFINITY;
    let mut mx = f32::NEG_INFINITY;
    for c in &matrix {
        let r = c.re;
        if r < mn { mn = r; }
        if r > mx { mx = r; }
    }
    let range = (mx - mn).max(1e-6);
    let mut img = GrayImage::new(size as u32, size as u32);
    for y in 0..size {
        for x in 0..size {
            let r = matrix[y * size + x].re;
            let norm = ((r - mn) / range).clamp(0.0, 1.0);
            img.put_pixel(x as u32, y as u32, Luma([(norm * 255.0) as u8]));
        }
    }
    Ok(EncodedGlint { image: img, bytes_used: stream.len(), capacity_bytes })
}