//! AeroGlint encoder (v3.0.4).
//!
//! Spectral camouflage: user photo occupies LOW frequencies (r < GUARD_INNER),
//! data occupies MID frequencies. Both domains are disjoint, so photo is
//! visible (blurred) but data integrity is preserved.

use anyhow::{anyhow, Result};
use image::{GrayImage, Luma, imageops::FilterType};
use rustfft::num_complex::Complex32;
use rustfft::FftPlanner;

use crate::AEROGLINT_GRID;

pub const GUARD_INNER: f32 = 0.20;
pub const GUARD_OUTER: f32 = 0.78;
pub const PILOT_RADIUS_NORM: f32 = 0.50;

pub const PILOT_ANGLES: [f32; 4] = [
    std::f32::consts::PI / 6.0,
    std::f32::consts::PI / 3.0,
    2.0 * std::f32::consts::PI / 3.0,
    5.0 * std::f32::consts::PI / 6.0,
];

// Softer pilots than v3.0.3 (were 8/7/6/5, too strong).
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

/// Canonical half-plane cells inside low-frequency circle (r < GUARD_INNER).
/// These cells are unused by data; photo spectrum lives here.
fn photo_cells(size: usize) -> Vec<(usize, usize)> {
    let c = size as f32 / 2.0;
    let inner_r = GUARD_INNER * c;
    let inner_r_sq = inner_r * inner_r;
    let mut out = Vec::new();
    for y in 0..size {
        for x in 0..size {
            let (mx, my) = ((size - x) % size, (size - y) % size);
            if x == mx && y == my { continue; }
            if (x > mx) || (x == mx && y > my) { continue; }
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            if dx * dx + dy * dy < inner_r_sq {
                out.push((x, y));
            }
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

/// Embed photo spectrum into low-frequency cells.
/// Photo pixels are mean-subtracted, FFT'd, then low-freq cells are copied
/// with a scale chosen so peak amplitude в‰€ 12.0 (strong enough to be visible
/// after IFFT, but confined to frequencies data never touches).
fn embed_photo_spectrum(matrix: &mut [Complex32], size: usize, photo: &GrayImage) {
    let resized = image::imageops::resize(photo, size as u32, size as u32, FilterType::Triangle);

    // Compute mean for DC removal (so photo doesn't shift the whole image)
    let n = (size * size) as f32;
    let mut sum = 0.0f32;
    for p in resized.pixels() { sum += p.0[0] as f32; }
    let mean = sum / n;

    let mut photo_matrix: Vec<Complex32> = resized.pixels()
        .map(|p| Complex32::new(p.0[0] as f32 - mean, 0.0))
        .collect();

    fft2d(&mut photo_matrix, size, false);

    let cells = photo_cells(size);
    if cells.is_empty() { return; }

    // Scale so max amplitude in low-freq band = 12.0
    let mut max_amp = 1e-6f32;
    for &(x, y) in &cells {
        let a = photo_matrix[y * size + x].norm();
        if a > max_amp { max_amp = a; }
    }
    let scale = 12.0 / max_amp;

    for &(x, y) in &cells {
        let v = photo_matrix[y * size + x] * scale;
        set_hermitian(matrix, size, x, y, v);
    }
}

/// Simple thick frame, compact: 10 px per side.
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

    // 2. Photo spectrum in low frequencies
    if let Some(p) = photo {
        embed_photo_spectrum(&mut matrix, size, p);
    }

    // 3. QPSK data in mid frequencies
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
        if src_a >= bits.len() && src_b >= bits.len() {
            continue;
        }
        let b1 = if src_a < bits.len() { bits[src_a] } else { 0 };
        let b2 = if src_b < bits.len() { bits[src_b] } else { 0 };
        let re = if b1 == 1 { 1.0 } else { -1.0 };
        let im = if b2 == 1 { 1.0 } else { -1.0 };
        set_hermitian(&mut matrix, size, x, y, Complex32::new(re, im));
    }

    // 4. IFFT
    fft2d(&mut matrix, size, true);

    // 5. Normalize real part to [0, 255]
    let mut min_r = f32::INFINITY;
    let mut max_r = f32::NEG_INFINITY;
    for cell in &matrix {
        let r = cell.re;
        if r < min_r { min_r = r; }
        if r > max_r { max_r = r; }
    }
    let range = (max_r - min_r).max(1e-6);
    let mut img = GrayImage::new(size as u32, size as u32);
    for y in 0..size {
        for x in 0..size {
            let r = matrix[y * size + x].re;
            let norm = ((r - min_r) / range).clamp(0.0, 1.0);
            img.put_pixel(x as u32, y as u32, Luma([(norm * 255.0) as u8]));
        }
    }

    Ok(EncodedGlint { image: img, bytes_used: stream.len(), capacity_bytes })
}