# FM Aero Code 2 - Roadmap

## Done

- v3.0-v3.6: AeroGlint core, AeroPack v20, AeroFlow, print pipeline
- v3.7-v3.9: DCT stego, QIM, LSB, Robust, DualB, FMS3 + Ed25519
- v3.10: per-install identity + root attestation
- v3.11: TSA, OpenTimestamps, fm_status/sign/verify
- v3.12-v3.13: Sauvola, docs
- v3.14: web mode toggle, GUI multi-sig (in-memory), WASM CI fix, .gitattributes
- v3.15.0: **Watson masking, ZKP (Schnorr NIZK), OTS upgrade**

## Next

### v3.16.x - deep algorithmic

- Progressive decoding (see docs/RESEARCH.md #1)
- Fountain codes (LT, #2)

### v3.17.x - performance

- WebGL / WebGPU FFT (#3)
- WebWorkers + WASM threads

### v3.18.x - density

- RGB-split (3x) (#5)
- 16-QAM / 64-QAM (#6)

### v4.x

- Full blockchain anchor UI (#7)
- AI-robust stego (#8)

## Not planned

- QR-code fallback (redundant)
- Detached GPG-style .sig files