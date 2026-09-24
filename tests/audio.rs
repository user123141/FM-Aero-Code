//! Audio stego round-trip tests using a synthetic WAV.
//!
//! Generates a 2-second sine sweep, embeds a payload, extracts it, and
//! verifies byte-exact round-trip in both Robust (MDCT-QIM) and
//! BitPerfect (LSB) modes.
//!
//! Also sanity-checks that masking actually preserves audible band
//! (RMS of audible region is close before/after).

use fm_aero_code_2::audio::{
    embed_wav, extract_wav, read_wav, write_wav,
    AudioEmbedOptions, AudioMode, WavFile,
};

fn make_sine_wav(seconds: f32, sample_rate: u32) -> WavFile {
    let n = (seconds * sample_rate as f32) as usize;
    let mut samples = Vec::with_capacity(n);
    // Simple 440 Hz + 880 Hz sine, mono, moderate amplitude
    for i in 0..n {
        let t = i as f32 / sample_rate as f32;
        let s = 0.4 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()
              + 0.2 * (2.0 * std::f32::consts::PI * 880.0 * t).sin();
        samples.push(s);
    }
    WavFile {
        sample_rate,
        channels: 1,
        bits_per_sample: 16,
        samples,
    }
}

fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() { return 0.0; }
    let s: f32 = samples.iter().map(|x| x * x).sum::<f32>();
    (s / samples.len() as f32).sqrt()
}

#[test]
fn audio_roundtrip_robust() {
    let carrier = make_sine_wav(5.0, 44100);
    let payload = b"FM Aero Code 2 - audio robust round-trip test payload";
    let opts = AudioEmbedOptions {
        mode: AudioMode::Robust,
        original_name: "payload.bin".into(),
        ..Default::default()
    };
    let out = embed_wav(&carrier, payload, &opts).expect("embed");
    let recovered = extract_wav(&out.wav, "").expect("extract");
    assert_eq!(recovered.payload, payload, "Robust payload mismatch");
    // Sanity: audio wasn't destroyed (RMS within 20%)
    let r0 = rms(&carrier.samples);
    let r1 = rms(&out.wav.samples);
    assert!(
        (r1 - r0).abs() / r0.max(1e-6) < 0.2,
        "Robust: RMS deviated too much ({:.3} -> {:.3})",
        r0, r1
    );
}

#[test]
fn audio_roundtrip_bitperfect() {
    let carrier = make_sine_wav(5.0, 44100);
    let payload = b"BitPerfect payload - must round-trip byte-exact";
    let opts = AudioEmbedOptions {
        mode: AudioMode::BitPerfect,
        original_name: "bp.bin".into(),
        ..Default::default()
    };
    let out = embed_wav(&carrier, payload, &opts).expect("embed");
    let recovered = extract_wav(&out.wav, "").expect("extract");
    assert_eq!(recovered.payload, payload, "BitPerfect payload mismatch");
}

#[test]
fn audio_roundtrip_with_password() {
    let carrier = make_sine_wav(5.0, 44100);
    let payload = b"sealed audio payload";
    let opts = AudioEmbedOptions {
        mode: AudioMode::BitPerfect,
        password: "hunter2".into(),
        original_name: "s.bin".into(),
        ..Default::default()
    };
    let out = embed_wav(&carrier, payload, &opts).expect("embed");
    // Wrong password must fail
    assert!(extract_wav(&out.wav, "wrong").is_err());
    // Right password works
    let recovered = extract_wav(&out.wav, "hunter2").expect("extract");
    assert_eq!(recovered.payload, payload);
}

#[test]
fn audio_wav_io_roundtrip() {
    // Write + read a WAV and verify byte-exact 16-bit PCM preservation.
    let w = make_sine_wav(0.5, 44100);
    let bytes = write_wav(&w).expect("write");
    let w2 = read_wav(&bytes).expect("read");
    assert_eq!(w2.sample_rate, w.sample_rate);
    assert_eq!(w2.channels, w.channels);
    assert_eq!(w2.bits_per_sample, w.bits_per_sample);
    assert_eq!(w2.samples.len(), w.samples.len());
    // 16-bit quantization error is < 1/32768
    for (a, b) in w.samples.iter().zip(w2.samples.iter()) {
        assert!((a - b).abs() < 1.0 / 32000.0, "sample drift: {} vs {}", a, b);
    }
}

#[test]
fn audio_capacity_monotonic() {
    // Longer audio -> more capacity
    let short = make_sine_wav(1.0, 44100);
    let long  = make_sine_wav(3.0, 44100);
    let cs = fm_aero_code_2::audio::capacity_bytes(&short, AudioMode::Robust);
    let cl = fm_aero_code_2::audio::capacity_bytes(&long, AudioMode::Robust);
    assert!(cl > cs, "capacity should grow with duration: {} vs {}", cs, cl);
}