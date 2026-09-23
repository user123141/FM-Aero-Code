use anyhow::{anyhow, Result};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const PACK_MAGIC: [u8; 2] = [0x7B, 0xA3];
const PACK_VERSION: u8 = 0xE2;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMethod { Raw = 0, Dpcm1 = 1, Dpcm2 = 2, Rle = 3, BwtMtfrle = 4, RawStored = 5, BcjZstd = 6 }

impl BlockMethod {
    pub fn from_byte(b: u8) -> Self {
        let k = b ^ 0x5A;
        match k { 1 => Self::Dpcm1, 2 => Self::Dpcm2, 3 => Self::Rle, 4 => Self::BwtMtfrle, 5 => Self::RawStored, 6 => Self::BcjZstd, _ => Self::Raw }
    }
    pub fn to_byte(self) -> u8 {
        let v = match self { Self::Raw=>0, Self::Dpcm1=>1, Self::Dpcm2=>2, Self::Rle=>3, Self::BwtMtfrle=>4, Self::RawStored=>5, Self::BcjZstd=>6 };
        v ^ 0x5A
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass { InPlace, Audio, Document, Textual, Generic, Lossless }

pub fn classify(data: &[u8]) -> DataClass {
    if data.len() < 8 { return DataClass::Generic; }
    let dt = crate::types::DataType::detect(data);
    match dt {
        crate::types::DataType::Audio | crate::types::DataType::Video => DataClass::Audio,
        crate::types::DataType::Image | crate::types::DataType::Archive => DataClass::InPlace,
        crate::types::DataType::Document => DataClass::Document,
        crate::types::DataType::Text => DataClass::Textual,
        _ => DataClass::Generic,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataProfile { Text, Smooth, Sparse, Structured, Mixed, Incompressible, Audio, AlreadyPacked, DocumentLike, Lossless, Executable }

impl DataProfile {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Text=>"text", Self::Smooth=>"smooth", Self::Sparse=>"sparse",
            Self::Structured=>"structured", Self::Mixed=>"mixed",
            Self::Incompressible=>"incompressible", Self::Audio=>"audio",
            Self::AlreadyPacked=>"already-packed", Self::DocumentLike=>"document",
            Self::Lossless=>"lossless", Self::Executable=>"executable",
        }
    }
    pub fn from_class(c: DataClass) -> Self {
        match c {
            DataClass::InPlace=>Self::AlreadyPacked, DataClass::Audio=>Self::Audio,
            DataClass::Document=>Self::DocumentLike, DataClass::Textual=>Self::Text,
            DataClass::Generic=>Self::Mixed, DataClass::Lossless=>Self::Lossless,
        }
    }
}

pub fn analyze(data: &[u8]) -> DataProfile {
    if data.is_empty() { return DataProfile::Mixed; }
    let n = data.len().min(4096);
    let s = &data[..n];
    let mut counts = [0u32; 256];
    for &b in s { counts[b as usize] += 1; }
    let mut e = 0.0f64;
    for &c in counts.iter() { if c > 0 { let p = c as f64 / n as f64; e -= p * p.log2(); } }
    if e > 7.5 { return DataProfile::Incompressible; }
    let p = s.iter().filter(|&&b| (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t').count();
    if p * 100 / n >= 85 { return DataProfile::Text; }
    let sd = (1..n).filter(|&i| (s[i] as i32 - s[i-1] as i32).unsigned_abs() <= 4).count();
    if sd * 100 / n >= 60 { return DataProfile::Smooth; }
    DataProfile::Mixed
}

pub fn block_size_for(class: DataClass) -> usize {
    match class {
        DataClass::Audio => 32 * 1024,
        DataClass::Textual => 8 * 1024,
        DataClass::Document => 16 * 1024,
        _ => 4 * 1024,
    }
}

fn dpcm1_enc(d: &[u8]) -> Vec<u8> {
    if d.is_empty() { return Vec::new(); }
    let mut o = Vec::with_capacity(d.len()); o.push(d[0]);
    for i in 1..d.len() { o.push(d[i].wrapping_sub(d[i-1])); }
    o
}
fn dpcm1_dec(d: &[u8]) -> Vec<u8> {
    if d.is_empty() { return Vec::new(); }
    let mut o = Vec::with_capacity(d.len()); o.push(d[0]);
    for i in 1..d.len() { let p = o[i-1]; o.push(p.wrapping_add(d[i])); }
    o
}
fn dpcm2_enc(d: &[u8]) -> Vec<u8> {
    if d.len() < 2 { return d.to_vec(); }
    let mut o = Vec::with_capacity(d.len()); o.push(d[0]); o.push(d[1].wrapping_sub(d[0]));
    for i in 2..d.len() {
        let d1 = d[i].wrapping_sub(d[i-1]);
        let d0 = d[i-1].wrapping_sub(d[i-2]);
        o.push(d1.wrapping_sub(d0));
    }
    o
}
fn dpcm2_dec(d: &[u8]) -> Vec<u8> {
    if d.len() < 2 { return d.to_vec(); }
    let mut o = Vec::with_capacity(d.len()); o.push(d[0]); o.push(d[0].wrapping_add(d[1]));
    for i in 2..d.len() {
        let p = o[i-1]; let p2 = o[i-2];
        let d0 = p.wrapping_sub(p2); let d1 = d0.wrapping_add(d[i]);
        o.push(p.wrapping_add(d1));
    }
    o
}
fn rle_enc(d: &[u8]) -> Vec<u8> {
    if d.is_empty() { return Vec::new(); }
    let mut o = Vec::with_capacity(d.len()); let mut i = 0usize;
    while i < d.len() {
        let byte = d[i]; let mut c: u8 = 1;
        while i + (c as usize) < d.len() && d[i + (c as usize)] == byte && c < 255 { c += 1; }
        o.push(c); o.push(byte); i += c as usize;
    }
    o
}
fn rle_dec(d: &[u8]) -> Vec<u8> {
    let mut o = Vec::new(); let mut i = 0usize;
    while i + 1 < d.len() {
        let c = d[i]; let b = d[i+1];
        for _ in 0..c { o.push(b); }
        i += 2;
    }
    o
}
fn bwt(d: &[u8]) -> Vec<u8> {
    if d.is_empty() { return Vec::new(); }
    let n = d.len();
    let mut sa: Vec<u32> = (0..n as u32).collect();
    sa.sort_by(|&i, &j| {
        let mut a = i as usize; let mut b = j as usize;
        for _ in 0..n {
            let ca = d[a]; let cb = d[b];
            if ca != cb { return ca.cmp(&cb); }
            a = (a + 1) % n; b = (b + 1) % n;
        }
        i.cmp(&j)
    });
    let mut o = Vec::with_capacity(n);
    for &idx in &sa { let i = idx as usize; o.push(if i == 0 { d[n-1] } else { d[i-1] }); }
    o
}
fn inverse_bwt(d: &[u8]) -> Vec<u8> {
    if d.is_empty() { return Vec::new(); }
    let n = d.len();
    let mut counts = [0usize; 256];
    for &b in d { counts[b as usize] += 1; }
    let mut starts = [0usize; 256];
    let mut sum = 0usize;
    for i in 0..256 { starts[i] = sum; sum += counts[i]; }
    let mut next = vec![0usize; n];
    let mut c = starts;
    for j in 0..n { let b = d[j] as usize; next[c[b]] = j; c[b] += 1; }
    let mut o = Vec::with_capacity(n);
    let mut k = next[0];
    for _ in 0..n { o.push(d[k]); k = next[k]; }
    o
}
fn mtf_enc(d: &[u8]) -> Vec<u8> {
    let mut t: [u8; 256] = [0; 256];
    for i in 0..256 { t[i] = i as u8; }
    let mut o = Vec::with_capacity(d.len());
    for &b in d {
        let mut pos = 0usize;
        while pos < 256 && t[pos] != b { pos += 1; }
        if pos >= 256 { pos = 255; }
        o.push(pos as u8);
        let v = t[pos]; let mut k = pos;
        while k > 0 { t[k] = t[k-1]; k -= 1; }
        t[0] = v;
    }
    o
}
fn mtf_dec(d: &[u8]) -> Vec<u8> {
    let mut t: [u8; 256] = [0; 256];
    for i in 0..256 { t[i] = i as u8; }
    let mut o = Vec::with_capacity(d.len());
    for &p in d {
        let pos = (p as usize).min(255);
        let v = t[pos]; let mut k = pos;
        while k > 0 { t[k] = t[k-1]; k -= 1; }
        t[0] = v;
        o.push(v);
    }
    o
}
fn bwt_pipe_enc(d: &[u8]) -> Vec<u8> { rle_enc(&mtf_enc(&bwt(d))) }
fn bwt_pipe_dec(d: &[u8]) -> Vec<u8> { inverse_bwt(&mtf_dec(&rle_dec(d))) }

#[cfg(not(target_arch = "wasm32"))]
fn backend_c(d: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut enc = zstd::stream::write::Encoder::new(&mut out, 3)?;
    use std::io::Write;
    enc.write_all(d)?;
    enc.finish()?;
    Ok(out)
}

#[cfg(not(target_arch = "wasm32"))]
fn backend_d(d: &[u8], _expected: usize) -> Result<Vec<u8>> {
    Ok(zstd::stream::decode_all(std::io::Cursor::new(d))?)
}

#[cfg(target_arch = "wasm32")]
fn backend_c(d: &[u8]) -> Result<Vec<u8>> {
    // WASM: miniz_oxide is disabled (panics on tiny inputs -> wasm unreachable).
    // Return input as-is. Caller compares sizes; result >= original -> RawStored.
    Ok(d.to_vec())
}

#[cfg(target_arch = "wasm32")]
fn backend_d(d: &[u8], _expected: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut dec = ruzstd::StreamingDecoder::new(d).map_err(|e| anyhow!("ruzstd init: {:?}", e))?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|e| anyhow!("ruzstd: {}", e))?;
    Ok(out)
}

pub struct PackResult {
    pub data: Vec<u8>,
    pub original_size: usize,
    pub block_count: usize,
    pub methods: Vec<BlockMethod>,
    pub class: DataClass,
}

fn encode_block(block: &[u8], class: DataClass) -> Result<(BlockMethod, Vec<u8>)> {
    match class {
        DataClass::InPlace | DataClass::Lossless =>
            Ok((BlockMethod::RawStored, block.to_vec())),
        DataClass::Audio => {
            let r = backend_c(block)?;
            let d1 = backend_c(&dpcm1_enc(block))?;
            let d2 = backend_c(&dpcm2_enc(block))?;
            let best = [(BlockMethod::Raw, r), (BlockMethod::Dpcm1, d1), (BlockMethod::Dpcm2, d2)]
                .into_iter().min_by_key(|(_, v)| v.len()).unwrap();
            if best.1.len() < block.len() { Ok(best) } else { Ok((BlockMethod::RawStored, block.to_vec())) }
        }
        DataClass::Document => {
            let b = backend_c(&bwt_pipe_enc(block))?;
            let r = backend_c(block)?;
            let best = [(BlockMethod::BwtMtfrle, b), (BlockMethod::Raw, r)]
                .into_iter().min_by_key(|(_, v)| v.len()).unwrap();
            if best.1.len() < block.len() { Ok(best) } else { Ok((BlockMethod::RawStored, block.to_vec())) }
        }
        DataClass::Textual => {
            let r = backend_c(block)?;
            let d1 = backend_c(&dpcm1_enc(block))?;
            let d2 = backend_c(&dpcm2_enc(block))?;
            let best = [(BlockMethod::Raw, r), (BlockMethod::Dpcm1, d1), (BlockMethod::Dpcm2, d2)]
                .into_iter().min_by_key(|(_, v)| v.len()).unwrap();
            if best.1.len() < block.len() { Ok(best) } else { Ok((BlockMethod::RawStored, block.to_vec())) }
        }
        DataClass::Generic => {
            let rz = backend_c(block)?;
            let d1 = backend_c(&dpcm1_enc(block))?;
            let d2 = backend_c(&dpcm2_enc(block))?;
            let rl = backend_c(&rle_enc(block))?;
            let bw = backend_c(&bwt_pipe_enc(block))?;
            let mut best = BlockMethod::RawStored;
            let mut bs = block.len();
            let mut ch = block.to_vec();
            if rz.len() < bs { best = BlockMethod::Raw; bs = rz.len(); ch = rz; }
            if d1.len() < bs { best = BlockMethod::Dpcm1; bs = d1.len(); ch = d1; }
            if d2.len() < bs { best = BlockMethod::Dpcm2; bs = d2.len(); ch = d2; }
            if rl.len() < bs { best = BlockMethod::Rle; bs = rl.len(); ch = rl; }
            if bw.len() < bs { best = BlockMethod::BwtMtfrle; ch = bw; }
            let _ = bs;
            Ok((best, ch))
        }
    }
}

pub fn aero_pack(data: &[u8]) -> Result<PackResult> {
    aero_pack_with_class(data, classify(data))
}
pub fn aero_pack_lossless(data: &[u8]) -> Result<PackResult> {
    aero_pack_with_class(data, DataClass::Lossless)
}

pub fn aero_pack_with_class(data: &[u8], class: DataClass) -> Result<PackResult> {
    if data.is_empty() { return Err(anyhow!("empty")); }
    let bs = block_size_for(class);
    let bc = (data.len() + bs - 1) / bs;

    #[cfg(not(target_arch = "wasm32"))]
    let encoded: Vec<(BlockMethod, Vec<u8>)> = (0..bc).into_par_iter()
        .map(|i| {
            let s = i * bs; let e = (s + bs).min(data.len());
            encode_block(&data[s..e], class)
        })
        .collect::<Result<Vec<_>>>()?;

    #[cfg(target_arch = "wasm32")]
    let encoded: Vec<(BlockMethod, Vec<u8>)> = (0..bc)
        .map(|i| {
            let s = i * bs; let e = (s + bs).min(data.len());
            encode_block(&data[s..e], class)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut out = Vec::with_capacity(data.len() + 16 + bc * 16);
    out.extend_from_slice(&PACK_MAGIC);
    out.push(PACK_VERSION);
    out.push(class as u8);
    out.extend_from_slice(&(bs as u32).to_le_bytes());
    out.extend_from_slice(&(bc as u32).to_le_bytes());
    let mut methods = Vec::with_capacity(bc);
    let mut i = 0usize;
    for (m, p) in encoded.into_iter() {
        let s = i * bs; let e = (s + bs).min(data.len());
        out.push(m.to_byte());
        out.extend_from_slice(&((e - s) as u32).to_le_bytes());
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&p);
        methods.push(m);
        i += 1;
    }
    Ok(PackResult { data: out, original_size: data.len(), block_count: bc, methods, class })
}

struct BlockEntry { m: BlockMethod, orig: usize, body: Vec<u8> }

fn decode_block(e: &BlockEntry) -> Result<Vec<u8>> {
    let raw = match e.m {
        BlockMethod::RawStored => e.body.clone(),
        BlockMethod::Raw => backend_d(&e.body, e.orig)?,
        BlockMethod::Dpcm1 => dpcm1_dec(&backend_d(&e.body, e.orig)?),
        BlockMethod::Dpcm2 => dpcm2_dec(&backend_d(&e.body, e.orig)?),
        BlockMethod::Rle => rle_dec(&backend_d(&e.body, e.orig)?),
        BlockMethod::BwtMtfrle => bwt_pipe_dec(&backend_d(&e.body, e.orig)?),
        BlockMethod::BcjZstd => {
            let mut buf = backend_d(&e.body, e.orig)?;
            bcj_x86_dec(&mut buf);
            buf
        }
    };
    if raw.len() != e.orig {
        return Err(anyhow!("block size {} != {}", raw.len(), e.orig));
    }
    Ok(raw)
}

pub fn aero_unpack(packed: &[u8]) -> Result<Vec<u8>> {
    if packed.len() < 12 { return Err(anyhow!("short")); }
    if packed[0..2] != PACK_MAGIC { return Err(anyhow!("bad magic")); }
    let bc = u32::from_le_bytes([packed[8],packed[9],packed[10],packed[11]]) as usize;
    let mut entries: Vec<BlockEntry> = Vec::with_capacity(bc);
    let mut pos = 12usize;
    for _ in 0..bc {
        if pos + 9 > packed.len() { return Err(anyhow!("hdr trunc")); }
        let m = BlockMethod::from_byte(packed[pos]);
        let o = u32::from_le_bytes([packed[pos+1],packed[pos+2],packed[pos+3],packed[pos+4]]) as usize;
        let c = u32::from_le_bytes([packed[pos+5],packed[pos+6],packed[pos+7],packed[pos+8]]) as usize;
        pos += 9;
        if pos + c > packed.len() { return Err(anyhow!("body trunc")); }
        let body = packed[pos..pos+c].to_vec();
        pos += c;
        entries.push(BlockEntry { m, orig: o, body });
    }

    #[cfg(not(target_arch = "wasm32"))]
    let blocks: Vec<Vec<u8>> = entries.par_iter()
        .map(decode_block)
        .collect::<Result<Vec<_>>>()?;

    #[cfg(target_arch = "wasm32")]
    let blocks: Vec<Vec<u8>> = entries.iter()
        .map(decode_block)
        .collect::<Result<Vec<_>>>()?;

    let total: usize = blocks.iter().map(|b| b.len()).sum();
    let mut out = Vec::with_capacity(total);
    for b in blocks { out.extend_from_slice(&b); }
    Ok(out)
}
// ---------------------------------------------------------------------
// v2.8.0: BCJ x86 filter (branch-call-jump normalization).
// Normalizes relative x86 CALL/JMP instructions to absolute offsets,
// making identical branch targets produce identical bytes. Improves
// compression of EXE/DLL by ~10-15% before zstd.
// ---------------------------------------------------------------------

pub fn bcj_x86_enc(data: &mut [u8]) {
    let n = data.len();
    if n < 5 { return; }
    let mut i = 0usize;
    while i + 4 < n {
        let b = data[i];
        if b == 0xE8 || b == 0xE9 {
            let rel = i32::from_le_bytes([data[i+1], data[i+2], data[i+3], data[i+4]]);
            let abs = (i as i64 + 5 + rel as i64) as u32;
            data[i+1] = abs as u8;
            data[i+2] = (abs >> 8) as u8;
            data[i+3] = (abs >> 16) as u8;
            data[i+4] = (abs >> 24) as u8;
            i += 5;
        } else {
            i += 1;
        }
    }
}

pub fn bcj_x86_dec(data: &mut [u8]) {
    let n = data.len();
    if n < 5 { return; }
    let mut i = 0usize;
    while i + 4 < n {
        let b = data[i];
        if b == 0xE8 || b == 0xE9 {
            let abs = u32::from_le_bytes([data[i+1], data[i+2], data[i+3], data[i+4]]);
            let rel = (abs as i64 - (i as i64 + 5)) as u32;
            data[i+1] = rel as u8;
            data[i+2] = (rel >> 8) as u8;
            data[i+3] = (rel >> 16) as u8;
            data[i+4] = (rel >> 24) as u8;
            i += 5;
        } else {
            i += 1;
        }
    }
}

/// Detect if data looks like a PE or ELF executable.
pub fn looks_like_exe(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    data.starts_with(b"MZ") || data.starts_with(&[0x7F, b'E', b'L', b'F'])
}