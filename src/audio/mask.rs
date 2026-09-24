#![allow(dead_code)]
//! Simplified psychoacoustic masking.
//!
//! For each MDCT coefficient, estimate a threshold below which modifications
//! are inaudible. Uses a smoothed spectral envelope, not a full Bark-scale
//! model. Fast, adequate for watermarking.

use crate::audio::mdct::N;

/// Smoothing half-window (in coefficient bins).
const SMOOTH: usize = 6;

pub fn masking_threshold(mdct: &[f32; N]) -> [f32; N] {
    // 1. Smoothed magnitude envelope
    let mut env = [0.0f32; N];
    for k in 0..N {
        let lo = k.saturating_sub(SMOOTH);
        let hi = (k + SMOOTH + 1).min(N);
        let mut sum = 0.0f32;
        for j in lo..hi { sum += mdct[j].abs(); }
        env[k] = sum / (hi - lo) as f32;
    }
    // 2. Perceptual threshold ~ -20 dB below local envelope + absolute floor
    let mut thr = [0.0f32; N];
    for k in 0..N {
        thr[k] = (env[k] * 0.1).max(0.001);
    }
    thr
}