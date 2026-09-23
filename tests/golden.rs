//! Golden test vectors: fixed inputs must produce identical outputs.

use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{encode_payload, CompressionMode, EncodeOptions};
use fm_aero_code_2::decoder::pipeline::decode_from_bytes;
use image::ImageEncoder;
use image::codecs::png::PngEncoder;

fn build_opts(password: &str) -> EncodeOptions {
    EncodeOptions {
        cipher: if password.is_empty() { CipherKind::None } else { CipherKind::SealV1 },
        password: password.to_string(),
        pad: true,
        compression: CompressionMode::LosslessPriority,
        original_name: "golden.bin".into(),
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

#[test]
fn golden_empty() {
    let opts = build_opts("");
    let r = encode_payload(&[], &opts).unwrap();
    let (w, h) = (r.image.width(), r.image.height());
    assert_eq!((w, h), (128, 128));
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(r.image.as_raw(), w, h, image::ExtendedColorType::L8)
        .unwrap();
    let dec = decode_from_bytes(&png, "", None).unwrap();
    assert_eq!(dec.payload.len(), 0);
    assert!(dec.hash_ok);
}

#[test]
fn golden_hello() {
    let opts = build_opts("");
    let r = encode_payload(b"Hello, FM Aero Code 2!", &opts).unwrap();
    let (w, h) = (r.image.width(), r.image.height());
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(r.image.as_raw(), w, h, image::ExtendedColorType::L8)
        .unwrap();
    let dec = decode_from_bytes(&png, "", None).unwrap();
    assert_eq!(dec.payload, b"Hello, FM Aero Code 2!");
    assert!(dec.hash_ok);
}

#[test]
fn golden_determinism() {
    // Same input -> same output (fixed timestamp).
    let opts = build_opts("");
    let r1 = encode_payload(b"determinism test", &opts).unwrap();
    let r2 = encode_payload(b"determinism test", &opts).unwrap();
    assert_eq!(r1.image.as_raw(), r2.image.as_raw());
}

#[test]
fn golden_password() {
    let opts = build_opts("hunter2");
    let r = encode_payload(b"secret", &opts).unwrap();
    let (w, h) = (r.image.width(), r.image.height());
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(r.image.as_raw(), w, h, image::ExtendedColorType::L8)
        .unwrap();
    let dec = decode_from_bytes(&png, "hunter2", None).unwrap();
    assert_eq!(dec.payload, b"secret");
    assert!(dec.hash_ok);
}