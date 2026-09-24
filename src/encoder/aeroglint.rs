//! AeroGlint encoder (v3.6.1).
//!
//! No photo overlay of any kind. Pure data + pilots + Hermitian symmetry.
//! Keeps smallest possible visual footprint for maximum decode reliability.

use anyhow::{anyhow, Result};
use image::{GrayImage, Luma};
use rustfft::num_complex::Complex32;
use rustfft::FftPlanner;

use crate::AEROGLINT_GRID;

pub const GUARD_INNER: f32 = 0.20;
pub const GUARD_OUTER: f32 = 0.86;
pub const PILOT_RADIUS_NORM: f32 = 0.50;

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

/// Soft decorative stars in the unused low-frequency region (r < GUARD_INNER).
/// Data cells never live here, so this is purely visual and safe for decode.
pub fn inject_stars(matrix: &mut [Complex32], size: usize, density: u16) {
    if density == 0 { return; }
    let half = size / 2;
    let mut rng = SplitMix64::new(0xA37C_D3F0_01BE_EF99);
    let n_stars = (density as usize).min(400);
    for _ in 0..n_stars {
        let a = (rng.next() as f32 / u64::MAX as f32) * std::f32::consts::TAU;
        let rr = (rng.next() as f32 / u64::MAX as f32) * 0.18;
        let r = rr * half as f32;
        let xf = half as f32 + r * a.cos();
        let yf = half as f32 + r * a.sin();
        let xi = xf.round() as isize;
        let yi = yf.round() as isize;
        if xi < 0 || yi < 0 || xi >= size as isize || yi >= size as isize { continue; }
        let xu = xi as usize;
        let yu = yi as usize;
        let tier = rng.next() as f32 / u64::MAX as f32;
        let amp = if tier < 0.75 {
            18.0 + (rng.next() as f32 / u64::MAX as f32) * 10.0
        } else if tier < 0.95 {
            45.0 + (rng.next() as f32 / u64::MAX as f32) * 15.0
        } else {
            90.0 + (rng.next() as f32 / u64::MAX as f32) * 40.0
        };
        let ph = (rng.next() as f32 / u64::MAX as f32) * std::f32::consts::TAU;
        let v = Complex32::new(amp * ph.cos(), amp * ph.sin());
        let mx = (size - xu) % size;
        let my = (size - yu) % size;
        if xu == mx && yu == my {
            matrix[yu * size + xu] = Complex32::new(v.re, 0.0);
        } else {
            matrix[yu * size + xu] = v;
            matrix[my * size + mx] = v.conj();
        }
    }
}

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

/// Encode stream. `_photo` is accepted for API compatibility but ignored.
pub fn encode_stream(
    stream: &[u8],
    photo: Option<&GrayImage>,
    _gamma: bool,
    mask: bool,
    star_density: u16,
    nebula: bool,
    frame_pattern: u8,
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
        if src_a >= bits.len() && src_b >= bits.len() { continue; }
        let b1 = if src_a < bits.len() { bits[src_a] } else { 0 };
        let b2 = if src_b < bits.len() { bits[src_b] } else { 0 };
        let re = if b1 == 1 { 1.0 } else { -1.0 };
        let im = if b2 == 1 { 1.0 } else { -1.0 };
        set_hermitian(&mut matrix, size, x, y, Complex32::new(re, im));
    }

    if let Some(p) = photo { render_photo_lowfreq(&mut matrix, size, p); }
    if nebula { inject_nebula(&mut matrix, size); }
    if frame_pattern != 0 { inject_frame(&mut matrix, size, frame_pattern); }
    if mask { inject_stars(&mut matrix, size, star_density); }

    fft2d(&mut matrix, size, true);

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

pub fn inject_nebula(matrix: &mut [Complex32], size: usize) {
    let half = size / 2;
    let mut rng = SplitMix64::new(0x5EED_11A0_5EED_11A0);
    for _ in 0..6 {
        let a = (rng.next() as f32 / u64::MAX as f32) * std::f32::consts::TAU;
        let rr = (rng.next() as f32 / u64::MAX as f32) * 0.15;
        let r = rr * half as f32;
        let cx = half as f32 + r * a.cos();
        let cy = half as f32 + r * a.sin();
        let rad = 1.5 + (rng.next() as f32 / u64::MAX as f32) * 2.5;
        let amp = 24.0 + (rng.next() as f32 / u64::MAX as f32) * 9.0;
        let ri = rad.ceil() as isize;
        for dy in -ri..=ri {
            for dx in -ri..=ri {
                let xi = cx.round() as isize + dx;
                let yi = cy.round() as isize + dy;
                if xi < 0 || yi < 0 || xi >= size as isize || yi >= size as isize { continue; }
                let d2 = (dx*dx + dy*dy) as f32;
                if d2 > rad * rad { continue; }
                let falloff = 1.0 - (d2.sqrt() / rad);
                let v = Complex32::new(amp * falloff, 0.0);
                let xu = xi as usize;
                let yu = yi as usize;
                let mx = (size - xu) % size;
                let my = (size - yu) % size;
                if xu == mx && yu == my {
                    matrix[yu * size + xu] += Complex32::new(v.re, 0.0);
                } else {
                    matrix[yu * size + xu] += v;
                    matrix[my * size + mx] += v.conj();
                }
            }
        }
    }
}

pub fn inject_frame(matrix: &mut [Complex32], size: usize, pattern: u8) {
    if pattern == 0 { return; }
    let half = size / 2;
    let amp = 36.0f32;
    let r_inner = (half as f32) * 0.20;
    let r_outer = (half as f32) * 0.24;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - half as f32;
            let dy = y as f32 - half as f32;
            let r = (dx*dx + dy*dy).sqrt();
            let keep = match pattern {
                1 => r >= r_inner && r <= r_outer,
                2 => (r >= r_inner && r <= r_outer) && ((dx.abs() < 1.2) || (dy.abs() < 1.2)),
                3 => (r >= r_inner && r <= r_outer) && (((x/4 + y/4) % 2) == 0),
                _ => false,
            };
            if !keep { continue; }
            let mx = (size - x) % size;
            let my = (size - y) % size;
            let v = Complex32::new(amp, 0.0);
            if x == mx && y == my {
                matrix[y * size + x] += v;
            } else {
                matrix[y * size + x] += v;
                matrix[my * size + mx] += v.conj();
            }
        }
    }
}

pub fn render_photo_lowfreq(matrix: &mut [Complex32], size: usize, photo: &GrayImage) {
    let half = size / 2;
    let small = image::imageops::resize(photo, 16, 16, image::imageops::FilterType::Triangle);
    let inner_r = (half as f32) * 0.18;
    for (xi, yi, px) in small.enumerate_pixels() {
        let fx = -inner_r + (xi as f32 / 15.0) * 2.0 * inner_r;
        let fy = -inner_r + (yi as f32 / 15.0) * 2.0 * inner_r;
        let cx = (half as f32 + fx).round() as isize;
        let cy = (half as f32 + fy).round() as isize;
        if cx < 0 || cy < 0 || cx >= size as isize || cy >= size as isize { continue; }
        let xu = cx as usize;
        let yu = cy as usize;
        let v = (px.0[0] as f32 - 128.0) / 128.0 * 1.5;
        let val = Complex32::new(v, 0.0);
        let mx = (size - xu) % size;
        let my = (size - yu) % size;
        if xu == mx && yu == my {
            matrix[yu * size + xu] = val;
        } else {
            matrix[yu * size + xu] = val;
            matrix[my * size + mx] = val.conj();
        }
    }
}

// ============================================================
// Progressive layout (v3.18.0)
// ============================================================

/// Cells sorted by radius (center-out). Lower index = closer to DC =
/// more robust against blur / low-pass filtering.
pub fn data_cells_priority(size: usize) -> Vec<(usize, usize)> {
    let mut cells = data_cells(size);
    let half = size as i32 / 2;
    cells.sort_by_key(|&(x, y)| {
        let fx = (x as i32 - half).abs();
        let fy = (y as i32 - half).abs();
        // Prefer cells close to center; break ties by (fx+fy)
        (fx.max(fy) as u64) << 32 | (fx + fy) as u64
    });
    cells
}

/// Encode with progressive layout:
///   cells[0..SHORT_HEADER_CELLS] : short header, RS(48,32)-protected,
///                                  QPSK, no permute
///   cells[SHORT_HEADER_CELLS..]  : permuted stream, QPSK
pub fn encode_stream_progressive(
    stream: &[u8],
    short_header: &crate::types::ShortHeader,
    _photo: Option<&GrayImage>,
    mask: bool,
    star_density: u16,
) -> Result<EncodedGlint> {
    use crate::types::{SHORT_HEADER_LEN, SHORT_HEADER_CELLS, SHORT_HEADER_RS_LEN};
    let size = AEROGLINT_GRID;
    let cells = data_cells_priority(size);
    if cells.len() < SHORT_HEADER_CELLS {
        return Err(anyhow!("not enough cells for short header"));
    }
    let payload_capacity = (cells.len() - SHORT_HEADER_CELLS) * 2 / 8;
    if stream.len() > payload_capacity {
        return Err(anyhow!(
            "stream {} > progressive payload capacity {}",
            stream.len(), payload_capacity
        ));
    }

    let mut matrix = vec![Complex32::new(0.0, 0.0); size * size];

    // Pilots
    let pilots = pilot_positions(size);
    for i in 0..4 {
        let (px, py) = pilots[i];
        set_hermitian(&mut matrix, size, px, py, PILOT_VALUES[i]);
    }

    // ----- short header -----
    let sh_bytes = short_header.to_bytes();
    debug_assert_eq!(sh_bytes.len(), SHORT_HEADER_LEN);
    let enc = reed_solomon::Encoder::new(SHORT_HEADER_RS_LEN - SHORT_HEADER_LEN);
    let coded = enc.encode(&sh_bytes);
    let mut sh_stream = Vec::with_capacity(SHORT_HEADER_RS_LEN);
    sh_stream.extend_from_slice(coded.data());
    sh_stream.extend_from_slice(coded.ecc());
    debug_assert_eq!(sh_stream.len(), SHORT_HEADER_RS_LEN);

    // Place short header bits directly into first cells (no permute)
    for (i, &(x, y)) in cells.iter().take(SHORT_HEADER_CELLS).enumerate() {
        let b1 = (sh_stream[i / 4] >> (7 - ((i * 2) % 8))) & 1;
        let b2 = (sh_stream[i / 4] >> (7 - ((i * 2 + 1) % 8))) & 1;
        let re = if b1 == 1 { 1.0 } else { -1.0 };
        let im = if b2 == 1 { 1.0 } else { -1.0 };
        set_hermitian(&mut matrix, size, x, y, Complex32::new(re, im));
    }

    // ----- payload (permuted) -----
    let total_bits = stream.len() * 8;
    let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
    for i in 0..total_bits {
        let byte = stream[i / 8];
        let bit = 7 - (i % 8);
        bits.push((byte >> bit) & 1);
    }
    let pay_cells = &cells[SHORT_HEADER_CELLS..];
    let mut perm: Vec<usize> = (0..pay_cells.len() * 2).collect();
    let mut rng = SplitMix64::new(interleave_seed());
    for i in (1..perm.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        perm.swap(i, j);
    }
    for (cell_idx, &(x, y)) in pay_cells.iter().enumerate() {
        let a = cell_idx * 2;
        let b = cell_idx * 2 + 1;
        if b >= perm.len() { break; }
        let src_a = perm[a];
        let src_b = perm[b];
        let b1 = if src_a < bits.len() { bits[src_a] } else { 0 };
        let b2 = if src_b < bits.len() { bits[src_b] } else { 0 };
        let re = if b1 == 1 { 1.0 } else { -1.0 };
        let im = if b2 == 1 { 1.0 } else { -1.0 };
        set_hermitian(&mut matrix, size, x, y, Complex32::new(re, im));
    }

    if mask { inject_stars(&mut matrix, size, star_density); }

    fft2d(&mut matrix, size, true);
    let mut mn = f32::INFINITY; let mut mx = f32::NEG_INFINITY;
    for c in &matrix {
        let r = c.re;
        if r < mn { mn = r; } if r > mx { mx = r; }
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
    Ok(EncodedGlint { image: img, bytes_used: stream.len(), capacity_bytes: payload_capacity })
}