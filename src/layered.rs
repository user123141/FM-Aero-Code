//! Layered encoding: AeroGlint pattern + Stego metadata in ONE image.
//!
//! AeroGlint produces a grayscale pattern. Stego DualB mode modifies
//! only B-channel LSBs (weight 11/100 in luma formula). Y = (30R + 59G + 11B) / 100
//! so +-1 in B -> +-0.11 in luma -> rounds back to the same u8.
//! AeroGlint luma is bit-identical after DualB embedding.
//!
//! Result: RGB PNG where both layers extract independently:
//!   - Grayscale (R=G=B) carries AeroGlint payload
//!   - B-channel LSB carries Stego metadata (author, license, sig)

use anyhow::Result;
use image::RgbImage;

use crate::decoder::pipeline::DecodeOutcome;
use crate::encoder::pipeline::{encode_payload, EncodeOptions, EncodeOutcome};
use crate::steganography::{embed, extract, StegoExtract, StegoMode, StegoOptions, StegoOutcome};

#[derive(Debug)]
pub struct LayeredOutcome {
    pub image: RgbImage,
    pub aero: EncodeOutcome,
    pub stego: StegoOutcome,
}

#[derive(Debug)]
pub struct LayeredDecodeOutcome {
    pub aero: Option<DecodeOutcome>,
    pub stego: Option<StegoExtract>,
    pub aero_error: Option<String>,
    pub stego_error: Option<String>,
}

/// Encode AeroGlint payload, then embed Stego metadata into B-channel LSB.
pub fn encode_layered(
    aero_payload: &[u8],
    stego_payload: &[u8],
    aero_opts: &EncodeOptions,
    stego_opts: &StegoOptions,
) -> Result<LayeredOutcome> {
    let aero = encode_payload(aero_payload, aero_opts)?;
    let (w, h) = (aero.image.width(), aero.image.height());

    let mut rgb = RgbImage::new(w, h);
    for (x, y, px) in aero.image.enumerate_pixels() {
        let v = px.0[0];
        rgb.put_pixel(x, y, image::Rgb([v, v, v]));
    }

    let mut opts = stego_opts.clone();
    opts.mode = StegoMode::DualB;
    let dyn_img = image::DynamicImage::ImageRgb8(rgb);
    let stego = embed(&dyn_img, stego_payload, &opts)?;

    Ok(LayeredOutcome {
        image: stego.image.clone(),
        aero,
        stego,
    })
}

/// Try both layers. Does not fail if only one succeeds.
pub fn decode_layered(data: &[u8], password: &str) -> LayeredDecodeOutcome {
    let (aero, aero_error) = match crate::decoder::pipeline::decode_from_bytes(data, password, None) {
        Ok(r) => (Some(r), None),
        Err(e) => (None, Some(e.to_string())),
    };

    let (stego, stego_error) = match image::load_from_memory(data) {
        Ok(img) => match extract(&img, password) {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.to_string())),
        },
        Err(e) => (None, Some(format!("image decode: {}", e))),
    };

    LayeredDecodeOutcome {
        aero,
        stego,
        aero_error,
        stego_error,
    }
}
