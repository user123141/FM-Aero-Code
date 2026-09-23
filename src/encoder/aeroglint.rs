//! AeroGlint encoder (v3.0.2).
//!
//! Spectral camouflage: user photo occupies LOW frequencies (r < GUARD_INNER),
//! data occupies MID frequencies (GUARD_INNER..GUARD_OUTER). They never overlap,
//! so a photo does not damage data integrity.

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

pub const PILOT_VALUES: [Complex32; 4] = [
    Complex32::new(4.0, 0.0),
    Complex32::new(3.0, 0.0),
    Complex32::new(2.0, 0.0),
    Complex32::new(1.0, 0.0),
];

pub const BORDER_FRAME: u32 = 4;
pub const BORDER_PAD: u32 = 20;
pub const BORDER_FINDER: u32 = 12;
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
    let pilot_exclude = 10i32;
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

fn gaussian_blur(img: &GrayImage, radius: f32) -> GrayImage {
    let sigma = radius.max(0.5);
    let k = (2.0 * sigma).ceil() as i32;
    let mut kernel = Vec::with_capacity((2 * k + 1) as usize);
    let mut sum = 0.0f32;
    for i in -k..=k {
        let v = (-(i as f32).powi(2) / (2.0 * sigma * sigma)).exp();
        kernel.push(v);
        sum += v;
    }
    for v in kernel.iter_mut() { *v /= sum; }
    let (w, h) = (img.width() as i32, img.height() as i32);
    let mut tmp = GrayImage::new(img.width(), img.height());
    for y in 0..h {
        for x in 0..w {
            let mut acc = 0.0f32;
            for i in -k..=k {
                let sx = (x + i).clamp(0, w - 1) as u32;
                acc += img.get_pixel(sx, y as u32).0[0] as f32 * kernel[(i + k) as usize];
            }
            tmp.put_pixel(x as u32, y as u32, Luma([acc.clamp(0.0, 255.0) as u8]));
        }
    }
    let mut out = GrayImage::new(img.width(), img.height());
    for y in 0..h {
        for x in 0..w {
            let mut acc = 0.0f32;
            for i in -k..=k {
                let sy = (y + i).clamp(0, h - 1) as u32;
                acc += tmp.get_pixel(x as u32, sy).0[0] as f32 * kernel[(i + k) as usize];
            }
            out.put_pixel(x as u32, y as u32, Luma([acc.clamp(0.0, 255.0) as u8]));
        }
    }
    out
}

/// Apply gamma pre-emphasis: value^(1/2.2).
pub fn apply_gamma(img: &mut GrayImage) {
    let inv_gamma = 1.0f32 / 2.2;
    for p in img.pixels_mut() {
        let v = p.0[0] as f32 / 255.0;
        p.0[0] = (v.powf(inv_gamma) * 255.0).clamp(0.0, 255.0) as u8;
    }
}

pub fn apply_circle_mask(img: &mut GrayImage) {
    let w = img.width() as f32;
    let h = img.height() as f32;
    let cx = w / 2.0;
    let cy = h / 2.0;
    let radius = w.min(h) * 0.48;
    for y in 0..img.height() {
        for x in 0..img.width() {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            if (dx * dx + dy * dy).sqrt() > radius {
                img.put_pixel(x, y, Luma([128]));
            }
        }
    }
}

/// Embed photo's spectrum into LOW frequencies (r < GUARD_INNER).
/// Those cells are not used by data, so no conflict.
fn embed_photo_spectrum(matrix: &mut [Complex32], size: usize, photo: &GrayImage) {
    let resized = image::imageops::resize(photo, size as u32, size as u32, FilterType::Triangle);
    let blurred = gaussian_blur(&resized, (size as f32 / 16.0).max(2.0));

    let mut photo_matrix: Vec<Complex32> = blurred.pixels()
        .map(|p| Complex32::new(p.0[0] as f32 - 128.0, 0.0))
        .collect();

    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(size);
    for y in 0..size {
        fft.process(&mut photo_matrix[y * size..(y + 1) * size]);
    }
    let mut col = vec![Complex32::new(0.0, 0.0); size];
    for x in 0..size {
        for y in 0..size { col[y] = photo_matrix[y * size + x]; }
        fft.process(&mut col);
        for y in 0..size { photo_matrix[y * size + x] = col[y]; }
    }

    let c = size as f32 / 2.0;
    let inner_r = GUARD_INNER * c;
    let inner_r_sq = inner_r * inner_r;
    let scale = 6.0f32;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            if dx * dx + dy * dy < inner_r_sq {
                matrix[y * size + x] = photo_matrix[y * size + x] * scale;
            }
        }
    }
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
    let f = BORDER_FINDER;
    let positions = [
        (BORDER_FRAME + 2, BORDER_FRAME + 2),
        (total - BORDER_FRAME - 2 - f, BORDER_FRAME + 2),
        (BORDER_FRAME + 2, total - BORDER_FRAME - 2 - f),
        (total - BORDER_FRAME - 2 - f, total - BORDER_FRAME - 2 - f),
    ];
    for &(px, py) in positions.iter() {
        for dy in 0..f {
            for dx in 0..f {
                let x = px + dx; let y = py + dy;
                if x >= total || y >= total { continue; }
                let is_border = dx < 2 || dy < 2 || dx >= f - 2 || dy >= f - 2;
                let is_center = dx >= f/2 - 1 && dx <= f/2 && dy >= f/2 - 1 && dy <= f/2;
                if is_border || is_center { out.put_pixel(x, y, Luma([0])); }
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
    gamma: bool,
    mask: bool,
) -> Result<EncodedGlint> {
    let size = AEROGLINT_GRID;
    let cells = data_cells(size);
    let capacity_bytes = cells.len() * 2 / 8;
    if stream.len() > capacity_bytes {
        return Err(anyhow!("stream {} > glint capacity {}", stream.len(), capacity_bytes));
    }
    let mut matrix = vec![Complex32::new(0.0, 0.0); size * size];
    let pilots = pilot_positions(size);
    for i in 0..4 {
        let (px, py) = pilots[i];
        set_hermitian(&mut matrix, size, px, py, PILOT_VALUES[i]);
    }
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
            set_hermitian(&mut matrix, size, x, y, Complex32::new(0.0, 0.0));
            continue;
        }
        let b1 = if src_a < bits.len() { bits[src_a] } else { 0 };
        let b2 = if src_b < bits.len() { bits[src_b] } else { 0 };
        let re = if b1 == 1 { 1.0 } else { -1.0 };
        let im = if b2 == 1 { 1.0 } else { -1.0 };
        set_hermitian(&mut matrix, size, x, y, Complex32::new(re, im));
    }

    // Spectral camouflage: photo into low frequencies
    if let Some(p) = photo {
        embed_photo_spectrum(&mut matrix, size, p);
    }

    let mut planner = FftPlanner::<f32>::new();
    let ifft = planner.plan_fft_inverse(size);
    for y in 0..size {
        ifft.process(&mut matrix[y * size..(y + 1) * size]);
    }
    let mut col = vec![Complex32::new(0.0, 0.0); size];
    for x in 0..size {
        for y in 0..size { col[y] = matrix[y * size + x]; }
        ifft.process(&mut col);
        for y in 0..size { matrix[y * size + x] = col[y]; }
    }
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
    if mask { apply_circle_mask(&mut img); }
    if gamma { apply_gamma(&mut img); }
    Ok(EncodedGlint { image: img, bytes_used: stream.len(), capacity_bytes })
}