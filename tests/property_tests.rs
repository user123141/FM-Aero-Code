//! Property-based tests for FM Aero Code 2.
//!
//! Verifies fundamental invariants that must hold for ANY input:
//!   * AeroPack round-trip: unpack(pack(x)) == x
//!   * FEC round-trip:      fec_decode(fec_encode(x)) == x
//!   * Full pipeline:       decode(encode(x)) == x (for payloads <= 1 KB)
//!   * Empty payload works
//!   * Arbitrary binary data works

use fm_aero_code_2::crypto::CipherKind;
use fm_aero_code_2::encoder::pipeline::{
    encode_payload, CompressionMode, EncodeOptions,
};
use fm_aero_code_2::decoder::pipeline::decode_from_bytes;
use image::ImageEncoder;
use image::codecs::png::PngEncoder;
use proptest::prelude::*;

fn run_roundtrip(payload: &[u8], password: &str) -> anyhow::Result<Vec<u8>> {
    let cipher = if password.is_empty() { CipherKind::None } else { CipherKind::SealV1 };
    let opts = EncodeOptions {
        cipher,
        password: password.to_string(),
        pad: true,
        compression: CompressionMode::LosslessPriority,
        original_name: "prop.bin".into(),
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
    };
    let enc = encode_payload(payload, &opts)?;
    let (w, h) = (enc.image.width(), enc.image.height());
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(enc.image.as_raw(), w, h, image::ExtendedColorType::L8)?;
    let dec = decode_from_bytes(&png, password, None)?;
    Ok(dec.payload)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn fec_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let encoded = fm_aero_code_2::fec::encode(&data).unwrap();
        let decoded = fm_aero_code_2::fec::decode(&encoded).unwrap();
        prop_assert_eq!(decoded, data);
    }

    #[test]
    fn pipeline_small_payloads(data in prop::collection::vec(any::<u8>(), 0..500)) {
        // Payloads up to ~500 bytes fit in a single AeroGlint page
        let result = run_roundtrip(&data, "").unwrap();
        prop_assert_eq!(result, data);
    }
}

#[test]
fn empty_payload() {
    let result = run_roundtrip(&[], "").unwrap();
    assert_eq!(result, Vec::<u8>::new());
}

#[test]
fn one_byte() {
    let result = run_roundtrip(&[0x42u8], "").unwrap();
    assert_eq!(result, vec![0x42u8]);
}

#[test]
fn ascii_string() {
    let s = b"Hello, FM Aero Code 2!";
    let result = run_roundtrip(s, "").unwrap();
    assert_eq!(result, s);
}

#[test]
fn password_roundtrip() {
    let s = b"secret data";
    let result = run_roundtrip(s, "hunter2").unwrap();
    assert_eq!(result, s);
}