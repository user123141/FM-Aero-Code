//! Self-test: encode -> decode in memory, no file I/O.

use anyhow::{anyhow, Result};
use image::ImageEncoder;
use image::codecs::png::PngEncoder;

use crate::crypto::CipherKind;
use crate::decoder::pipeline::decode_from_bytes;
use crate::encoder::apng::write_apng_to_vec;
use crate::encoder::pipeline::{encode_aeroflow, encode_payload, CompressionMode, EncodeOptions};

#[derive(Debug, Clone)]
pub struct SelfTestReport {
    pub input_bytes: usize,
    pub png_bytes: usize,
    pub decoded_bytes: usize,
    pub match_ok: bool,
    pub png_width: u32,
    pub png_height: u32,
    pub multi_page: bool,
}

fn build_opts(password: &str, name: &str) -> EncodeOptions {
    let cipher = if password.is_empty() { CipherKind::None } else { CipherKind::SealV1 };
    EncodeOptions {
        cipher,
        password: password.to_string(),
        pad: true,
        compression: CompressionMode::LosslessPriority,
        original_name: name.to_string(),
        center_logo: None,
        signing_key: None,
        hmac_enabled: true,
        auto_lossless_media: true,
        recipient_key: None,
        recipients: Vec::new(),
        gps: None,
        resilience_level: 0,
        border: false,
        gamma: false,
        mask: false,
        progress: None,
        stars: false,
        star_density: 60,
        nebula: false,
        frame_pattern: 0,
        sign_with_app_identity: false,
        extra_signatures: Vec::new(),
        tsa_block: None,
    }
}

pub fn roundtrip(payload: &[u8], password: &str) -> Result<SelfTestReport> {
    let opts = build_opts(password, "selftest.bin");

    match encode_payload(payload, &opts) {
        Ok(enc) => {
            let (w, h) = (enc.image.width(), enc.image.height());
            let mut png: Vec<u8> = Vec::new();
            PngEncoder::new(&mut png)
                .write_image(enc.image.as_raw(), w, h, image::ExtendedColorType::L8)
                .map_err(|e| anyhow!("png: {}", e))?;
            let dec = decode_from_bytes(&png, password, None)?;
            return Ok(SelfTestReport {
                input_bytes: payload.len(),
                png_bytes: png.len(),
                decoded_bytes: dec.payload.len(),
                match_ok: dec.payload == payload,
                png_width: w,
                png_height: h,
                multi_page: false,
            });
        }
        Err(_) => { /* fall through */ }
    }

    let flow = encode_aeroflow(payload, &opts)?;
    let apng = write_apng_to_vec(&flow.frames, 4)?;
    let dec = decode_from_bytes(&apng, password, None)?;
    let first = &flow.frames[0];
    Ok(SelfTestReport {
        input_bytes: payload.len(),
        png_bytes: apng.len(),
        decoded_bytes: dec.payload.len(),
        match_ok: dec.payload == payload,
        png_width: first.width(),
        png_height: first.height(),
        multi_page: true,
    })
}

pub fn selftest_string(s: &str) -> Result<SelfTestReport> {
    roundtrip(s.as_bytes(), "")
}

pub fn selftest_string_with_password(s: &str, pw: &str) -> Result<SelfTestReport> {
    roundtrip(s.as_bytes(), pw)
}