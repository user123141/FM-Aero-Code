# FM Aero Code 2 - Roadmap

Living document. Priorities shift as we ship.

## Done

- **v3.0.0** - AeroGlint spectral encoder (QPSK over 2D FFT)
- **v3.3.0** - AeroPack v20 adaptive compressor + BCJ x86
- **v3.5.0** - AeroFlow multi-page APNG with RS resilience
- **v3.6.0** - Reed-Solomon page recovery, print pipeline (PNG/HTML/SVG/PDF)
- **v3.6.5** - Progress bar with ETA / pps / bytes-per-second
- **v3.6.7** - Memory-friendly release profile (lto=off)
- **v3.7.0** - DCT steganography (embed in R channel, QIM, FEC)
- **v3.7.1** - Fixed stego round-trip, no YCbCr drift

## In progress / next

### Stego improvements
- [ ] **Robust mode** (spread-spectrum, Delta=24) - survives JPEG q=60
- [ ] **Strength slider** in GUI (Delta=6..24)
- [ ] **Capacity estimation** live update as you type
- [ ] **Multi-image embed** - one payload across N carriers
- [ ] **Stego in WASM web UI** (`web/stego.html`)
- [ ] **JPEG output** support (currently PNG only)

### Camera / scanner
- [ ] **Finder patterns** (QR-like corner markers) for auto-crop
- [ ] **Perspective warp** in WASM decoder
- [ ] **Adaptive binarization** (Sauvola / integral image)
- [ ] **Auto-shutter** in web scanner (interval + confidence)
- [ ] **Focus lock** + torch control
- [ ] **Pilot-based equalization** (CSI) - amplify faded high freqs
- [ ] **Soft-decision RS** (LPR erasures) - 2x error correction

### AeroGlint improvements
- [ ] **Progressive decoding** - metadata in low freqs, payload in high
- [ ] **16-QAM / 64-QAM** adaptive constellations (2-3x density)
- [ ] **Dot-gain pre-emphasis** for printer compensation
- [ ] **Watermark text** in low-freq (visual signature)
- [ ] **Inter-frame APNG compression** (video mode)
- [ ] **Fountain codes** (LT / Raptor) for >=50% loss recovery

### Web / WASM
- [ ] **WebWorkers + WASM threads** (wasm-bindgen-rayon)
- [ ] **WebGL/WebGPU FFT** for 60fps scanning
- [ ] **Zero-copy WASM pipeline** (fixed pointer to frame buffer)
- [ ] **PWA offline mode** full polish
- [ ] **Share target API** (share photo to FM Aero Code on Android)

### AeroPack / compression
- [ ] **Neural predictor** for text (tiny learned model)
- [ ] **Better BWT** (currently O(n log n) na.ive)
- [ ] **Delta filters** per data class (already partial)

### GUI / UX
- [ ] **Presets** (Web / Print / Archive) - one-click settings
- [ ] **Batch drag-and-drop** - multiple files at once
- [ ] **Live camera preview** in native GUI (nokhwa crate)
- [ ] **Theme: light** (currently dark only)
- [ ] **i18n** (currently English only)

## Long-term / research

- DCT steganography in multiple color channels (Y + Cb + Cr)
- Combine AeroGlint + stego in one image (dual channel)
- ML-based decode for heavy distortion
- Hardware acceleration on mobile (Metal / Vulkan compute)
- Paper fingerprint for authentication

## Contributing

Open an issue with the `enhancement` label. Priority is set by:
1. Correctness (bugs first)
2. Cross-platform reliability
3. Speed
4. Feature richness

## Versioning

Semantic. Format compatibility:
- AeroHeader v2 (current) - stable since v3.0
- AeroPack v20 - stable since v3.3
- Stego FMS1 format - new in v3.7

Breaking format changes bump major. New features bump minor. Bugfixes bump patch.