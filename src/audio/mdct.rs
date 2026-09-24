#![allow(dead_code)]
//! MDCT (Modified Discrete Cosine Transform) for audio stego.
//!
//! N = 512 coefficients from a 1024-sample window, 50% overlap (hop = 512).
//! Sine window satisfies Princen-Bradley: w[n]^2 + w[n+N]^2 = 1.
//! Direct O(N^2) formula; N=512 keeps it fast enough for CLI.
//!
//! Forward:  X[k] = sum_{n=0}^{2N-1} x[n] * cos(pi/N * (n + 0.5 + N/2) * (k + 0.5))
//! Inverse:  y[n] = (2/N) * sum_{k=0}^{N-1} X[k] * cos(pi/N * (n + 0.5 + N/2) * (k + 0.5))
//! Reconstruction: window IMDCT output with sine window, overlap-add.

use std::f32::consts::PI;

pub const N: usize = 512;
pub const WINDOW: usize = 2 * N;
pub const HOP: usize = N;

pub fn sine_window() -> Vec<f32> {
    let mut w = vec![0.0f32; WINDOW];
    for n in 0..WINDOW {
        w[n] = (PI / WINDOW as f32 * (n as f32 + 0.5)).sin();
    }
    w
}

pub fn mdct(input: &[f32; WINDOW], out: &mut [f32; N]) {
    let pi_n = PI / N as f32;
    let n_half_off = N as f32 / 2.0 + 0.5;
    for k in 0..N {
        let kp = k as f32 + 0.5;
        let mut s = 0.0f32;
        for n in 0..WINDOW {
            let phase = pi_n * (n as f32 + n_half_off) * kp;
            s += input[n] * phase.cos();
        }
        out[k] = s;
    }
}

pub fn imdct(input: &[f32; N], out: &mut [f32; WINDOW]) {
    let pi_n = PI / N as f32;
    let n_half_off = N as f32 / 2.0 + 0.5;
    let scale = 2.0 / N as f32;
    for n in 0..WINDOW {
        let mut s = 0.0f32;
        for k in 0..N {
            let phase = pi_n * (n as f32 + n_half_off) * (k as f32 + 0.5);
            s += input[k] * phase.cos();
        }
        out[n] = s * scale;
    }
}