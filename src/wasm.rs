#![cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use std::collections::BTreeMap;
use crate::decoder::aeroglint::decode_luma;
use crate::decoder::pipeline::{decode_apng_streams, finish_from_stream};
use crate::encoder::pipeline::{encode_payload, CompressionMode, EncodeOptions};
use crate::crypto::CipherKind;
use crate::types::AeroHeader;
use image::GrayImage;

#[wasm_bindgen(start)]
pub fn wasm_init() { console_error_panic_hook::set_once(); }

#[wasm_bindgen]
pub fn wasm_version() -> String { crate::VERSION.into() }

fn base_opts(password: &str, filename: &str) -> EncodeOptions {
    EncodeOptions {
        cipher: if password.is_empty() { CipherKind::None } else { CipherKind::SealV1 },
        password: password.to_string(),
        pad: true,
        compression: CompressionMode::LosslessPriority,
        original_name: filename.to_string(),
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

#[wasm_bindgen]
pub fn encode_payload_wasm(data: &[u8], password: &str, filename: &str) -> Vec<u8> {
    let opts = base_opts(password, filename);
    encode_to_png_or_apng(data, &opts)
}

#[wasm_bindgen]
pub fn encode_payload_wasm_ex(
    data: &[u8], password: &str, filename: &str,
    resilience_level: u8, border: bool, gamma: bool, mask: bool,
) -> Vec<u8> {
    let mut opts = base_opts(password, filename);
    opts.resilience_level = resilience_level;
    opts.border = border;
    opts.gamma = gamma;
    opts.mask = mask;
    encode_to_png_or_apng(data, &opts)
}

fn encode_to_png_or_apng(data: &[u8], opts: &EncodeOptions) -> Vec<u8> {
    if let Ok(r) = encode_payload(data, opts) {
        let mut png = Vec::new();
        {
            use image::ImageEncoder;
            use image::codecs::png::PngEncoder;
            if PngEncoder::new(&mut png)
                .write_image(r.image.as_raw(), r.image.width(), r.image.height(),
                    image::ExtendedColorType::L8).is_err() { return Vec::new(); }
        }
        return png;
    }
    if let Ok(f) = crate::encoder::pipeline::encode_aeroflow(data, opts) {
        if let Ok(apng) = crate::encoder::apng::write_apng_to_vec(&f.frames, 4) {
            return apng;
        }
    }
    Vec::new()
}

#[wasm_bindgen]
pub fn decode_payload_wasm(png: &[u8], password: &str) -> Vec<u8> {
    match crate::decoder::pipeline::decode_from_bytes(png, password, None) {
        Ok(r) => r.payload,
        Err(_) => Vec::new(),
    }
}

#[wasm_bindgen]
pub fn camera_constraints_json(front: bool) -> String {
    let f = if front { "user" } else { "environment" };
    format!("{{\"video\":{{\"facingMode\":\"{}\",\"width\":{{\"ideal\":1920}},\"height\":{{\"ideal\":1080}}}},\"audio\":false}}", f)
}

#[wasm_bindgen]
pub fn generate_recipient_keypair() -> Vec<u8> {
    let kp = crate::crypto::generate_recipient();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(kp.secret.to_bytes().as_ref());
    out.extend_from_slice(kp.public.as_bytes());
    out
}

#[wasm_bindgen]
pub struct WasmScanner {
    pages: BTreeMap<u16, Vec<u8>>,
    total: u16,
    last_rotation_deg: f32,
    last_noise_floor: f32,
}

#[wasm_bindgen]
impl WasmScanner {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { pages: BTreeMap::new(), total: 0, last_rotation_deg: 0.0, last_noise_floor: 0.0 }
    }
    pub fn reset(&mut self) {
        self.pages.clear();
        self.total = 0;
        self.last_rotation_deg = 0.0;
        self.last_noise_floor = 0.0;
    }
    pub fn received_count(&self) -> u32 { self.pages.len() as u32 }

    /// Last measured rotation in degrees (from decode_luma).
    pub fn last_rotation(&self) -> f32 { self.last_rotation_deg }

    /// Last measured noise floor (threshold actually used).
    pub fn last_noise_floor(&self) -> f32 { self.last_noise_floor }

    /// Pages we still need (ARQ feedback). Empty if complete or not started.
    pub fn missing_pages(&self) -> Vec<u16> {
        if self.total == 0 { return Vec::new(); }
        (0..self.total).filter(|i| !self.pages.contains_key(i)).collect()
    }

    /// Comma-separated list of missing page indices, for UI display.
    pub fn missing_pages_str(&self) -> String {
        self.missing_pages().iter().map(|i| i.to_string())
            .collect::<Vec<_>>().join(",")
    }
    pub fn total_count(&self) -> u32 { self.total as u32 }

    pub fn feed_frame(&mut self, rgba: &[u8], w: u32, h: u32, password: &str) -> String {
        if rgba.len() < (w as usize) * (h as usize) * 4 {
            return r#"{"ok":false,"error":"frame too small"}"#.into();
        }
        let mut luma = GrayImage::new(w, h);
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 4) as usize;
                let r = rgba[i] as u32;
                let g = rgba[i + 1] as u32;
                let b = rgba[i + 2] as u32;
                let l = ((r * 30 + g * 59 + b * 11) / 100) as u8;
                luma.put_pixel(x, y, image::Luma([l]));
            }
        }
        let glint = match decode_luma(&luma) {
            Ok(g) => g,
            Err(e) => return format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e.to_string())),
        };
        self.last_rotation_deg = glint.rotation_deg;
        self.last_noise_floor = glint.noise_floor;

        let stream = match crate::fec::decode(&glint.stream) {
            Ok(s) => s,
            Err(e) => return format!(r#"{{"ok":false,"error":"fec: {}"}}"#, json_escape(&e.to_string())),
        };
        let header = match AeroHeader::from_bytes(&stream) {
            Some(h) => h,
            None => return r#"{"ok":false,"error":"bad header"}"#.into(),
        };
        if header.page_total > 0 { self.total = header.page_total; }
        let idx = header.page_index;
        if !self.pages.contains_key(&idx) {
            self.pages.insert(idx, stream.clone());
        }
        if self.total <= 1 || self.pages.len() as u16 >= self.total {
            let streams: Vec<Vec<u8>> = self.pages.values().cloned().collect();
            let result = if streams.len() == 1 {
                finish_from_stream(&streams[0], password)
            } else {
                decode_apng_streams(&streams, password)
            };
            match result {
                Ok(r) => {
                    let b64 = base64_encode(&r.payload);
                    let received = self.pages.len();
                    let total = self.total;
                    self.reset();
                    return format!(
                        r#"{{"ok":true,"name":"{}","type":"{}","sha":"{}","size":{},"progress":"{}/{}","payload_b64":"{}"}}"#,
                        json_escape(&r.original_filename),
                        r.header.data_type.label(),
                        r.sha256,
                        r.payload.len(),
                        received, total,
                        b64,
                    );
                }
                Err(e) => return format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e.to_string())),
            }
        }
        format!(
            r#"{{"ok":false,"partial":true,"received":{},"total":{},"page_index":{}}}"#,
            self.pages.len(), self.total, idx,
        )
    }
}
impl Default for WasmScanner { fn default() -> Self { Self::new() } }

fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for c in data.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[wasm_bindgen]
pub fn stego_capacity_wasm(width: u32, height: u32) -> usize {
    crate::steganography::capacity_bytes(width, height)
}

#[wasm_bindgen]
pub fn stego_embed_wasm(carrier_png: &[u8], payload: &[u8], password: &str) -> Vec<u8> {
    let Ok(carrier) = image::load_from_memory(carrier_png) else { return Vec::new(); };
    let opts = crate::steganography::StegoOptions {
        password: password.to_string(),
        original_name: String::new(),
        mode: crate::steganography::StegoMode::BitPerfect,
        author: String::new(),
        license: String::new(),
        signing_seed: None,
    };
    let Ok(out) = crate::steganography::embed(&carrier, payload, &opts) else { return Vec::new(); };
    let mut png: Vec<u8> = Vec::new();
    {
        use image::ImageEncoder;
        use image::codecs::png::PngEncoder;
        if PngEncoder::new(&mut png)
            .write_image(out.image.as_raw(), out.image.width(), out.image.height(),
                image::ExtendedColorType::Rgb8).is_err() { return Vec::new(); }
    }
    png
}

#[wasm_bindgen]
pub fn stego_extract_wasm(stego_png: &[u8], password: &str) -> Vec<u8> {
    let Ok(img) = image::load_from_memory(stego_png) else { return Vec::new(); };
    match crate::steganography::extract(&img, password) {
        Ok(r) => r.payload,
        Err(_) => Vec::new(),
    }
}

/// Extract + return JSON metadata {ok, name, size, sha, cipher, payload_b64}.
#[wasm_bindgen]
pub fn stego_extract_wasm_ex(stego_png: &[u8], password: &str) -> String {
    let Ok(img) = image::load_from_memory(stego_png) else {
        return "{\"ok\":false,\"error\":\"image decode\"}".into();
    };
    match crate::steganography::extract(&img, password) {
        Ok(r) => {
            let b64 = base64_encode(&r.payload);
            format!(
                "{{\"ok\":true,\"name\":\"{}\",\"size\":{},\"sha\":\"{}\",\"cipher\":\"{}\",\"payload_b64\":\"{}\"}}",
                json_escape(&r.name),
                r.payload.len(),
                r.content_hash,
                r.cipher.label(),
                b64,
            )
        }
        Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string())),
    }
}