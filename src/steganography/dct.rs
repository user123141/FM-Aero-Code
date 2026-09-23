//! 8x8 DCT and inverse DCT, direct formula (no FFT).
//! For 512x512 images (4096 blocks) this runs in a few milliseconds.

use std::f32::consts::PI;

pub const BLOCK: usize = 8;
pub const BLOCK_AREA: usize = 64;

/// Forward DCT on one 8x8 block (row-major float input -> row-major DCT).
pub fn dct8x8(input: &[f32; BLOCK_AREA], output: &mut [f32; BLOCK_AREA]) {
    let mut tmp = [0.0f32; BLOCK_AREA];
    // Rows
    for y in 0..8 {
        for u in 0..8 {
            let mut s = 0.0f32;
            for x in 0..8 {
                s += input[y * 8 + x]
                    * (((2.0 * x as f32 + 1.0) * u as f32 * PI) / 16.0).cos();
            }
            let cu = if u == 0 { 1.0 / (2.0f32).sqrt() } else { 1.0 };
            tmp[y * 8 + u] = s * cu * 0.5;
        }
    }
    // Columns
    for x in 0..8 {
        for v in 0..8 {
            let mut s = 0.0f32;
            for y in 0..8 {
                s += tmp[y * 8 + x]
                    * (((2.0 * y as f32 + 1.0) * v as f32 * PI) / 16.0).cos();
            }
            let cv = if v == 0 { 1.0 / (2.0f32).sqrt() } else { 1.0 };
            output[v * 8 + x] = s * cv * 0.5;
        }
    }
}

/// Inverse DCT on one 8x8 block.
pub fn idct8x8(input: &[f32; BLOCK_AREA], output: &mut [f32; BLOCK_AREA]) {
    let mut tmp = [0.0f32; BLOCK_AREA];
    // Columns (inverse order)
    for x in 0..8 {
        for y in 0..8 {
            let mut s = 0.0f32;
            for v in 0..8 {
                let cv = if v == 0 { 1.0 / (2.0f32).sqrt() } else { 1.0 };
                s += cv
                    * input[v * 8 + x]
                    * (((2.0 * y as f32 + 1.0) * v as f32 * PI) / 16.0).cos();
            }
            tmp[y * 8 + x] = s * 0.5;
        }
    }
    // Rows
    for y in 0..8 {
        for x in 0..8 {
            let mut s = 0.0f32;
            for u in 0..8 {
                let cu = if u == 0 { 1.0 / (2.0f32).sqrt() } else { 1.0 };
                s += cu
                    * tmp[y * 8 + u]
                    * (((2.0 * x as f32 + 1.0) * u as f32 * PI) / 16.0).cos();
            }
            output[y * 8 + x] = s * 0.5;
        }
    }
}

/// Linear indices of the coefficients we use for embedding.
/// We skip DC (0) and low-freq (1..=9), use all remaining 54.
pub const EMBED_IDX: [usize; 54] = [
    10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33,
    34, 35, 36, 37, 38, 39, 40, 41,
    42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57,
    58, 59, 60, 61, 62, 63,
];

/// LSB mode: 11 mid-frequency AC coefficients per 8x8 block.
/// These survive IDCT -> round -> DCT with bit-perfect precision.
pub const EMBED_IDX_LSB: [usize; 11] = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

pub const LSB_BITS_PER_BLOCK: usize = EMBED_IDX_LSB.len();
