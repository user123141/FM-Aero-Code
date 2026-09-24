# FM Aero Code 2 - Roadmap

## Done

- v3.0-v3.6: AeroGlint core, AeroPack v20, AeroFlow, print pipeline
- v3.7-v3.9: DCT stego, QIM, LSB, Robust, DualB, FMS3 with Ed25519
- v3.10: Per-install identity + root attestation
- v3.11: TSA, OpenTimestamps, fm_status, fm_sign, fm_verify
- v3.12-v3.13: Sauvola binarization, docs
- v3.14: Web mode toggle, GUI multi-sig in-memory, WASM CI fix
- v3.14.7: Web stego carrier form, ARQ UI, scanner HUD, .gitattributes

## Next (concrete)

### v3.15.x - web polish

- Progressive scroll preview
- Better error states
- Offline manifest bump

### v3.16.x - deep algorithmic (see docs/RESEARCH.md)

- Progressive decoding (metadata low-freq)
- Fountain codes (LT, 50% loss tolerance)

### v3.17.x - performance

- WebGL / WebGPU FFT
- WebWorkers + WASM threads
- Zero-copy pipeline

### v3.18.x - density

- 16-QAM / 64-QAM adaptive
- RGB-split (3 independent FFT grids)

### v4.x - attestation+

- Blockchain anchor (Bitcoin OTS)
- Zero-knowledge proof of ownership
- AI-robust stego

## Not planned

- QR-code fallback (redundant)
- Detached GPG-style .sig files