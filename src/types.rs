pub const AERO_MAGIC: [u8; 3] = *b"FM2";
pub const AERO_VERSION: u8 = 2;
pub const AERO_HEADER_SIZE: usize = 128;

pub const HEADER_FLAG_PADDED:    u8 = 1 << 0;
pub const HEADER_FLAG_MULTIPAGE: u8 = 1 << 1;
pub const HEADER_FLAG_NAMED:     u8 = 1 << 3;
pub const HEADER_FLAG_SIGNED:    u8 = 1 << 5;
pub const HEADER_FLAG_HMAC:      u8 = 1 << 6;
pub const HEADER_FLAG_APP_SIGNED: u8 = 1 << 4;
pub const HEADER_FLAG_GAMMA:     u8 = 1 << 7;

/// Resilience level (data/parity split per group).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResilienceLevel { Off = 0, Low = 1, Balanced = 2, High = 3, Extreme = 4 }

impl ResilienceLevel {
    pub fn from_u8(v: u8) -> Self {
        match v { 1 => Self::Low, 2 => Self::Balanced, 3 => Self::High, 4 => Self::Extreme, _ => Self::Off }
    }
    pub fn as_u8(self) -> u8 { self as u8 }
    pub fn split(self) -> (usize, usize) {
        match self {
            Self::Off      => (200, 0),
            Self::Low      => (190, 10),
            Self::Balanced => (180, 20),
            Self::High     => (150, 50),
            Self::Extreme  => (100, 100),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Off      => "Off",
            Self::Low      => "Low (5%)",
            Self::Balanced => "Balanced (10%)",
            Self::High     => "High (25%)",
            Self::Extreme  => "Extreme (50%)",
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Text = 0, Audio = 1, Image = 2, Document = 3,
    Raw = 4, Executable = 5, Archive = 6, Video = 7,
}

impl DataType {
    pub fn from_byte(b: u8) -> Self {
        match b { 0=>Self::Text,1=>Self::Audio,2=>Self::Image,3=>Self::Document,
                  4=>Self::Raw,5=>Self::Executable,6=>Self::Archive,7=>Self::Video,_=>Self::Raw }
    }
    pub fn label(&self) -> &'static str {
        match self { Self::Text=>"Text",Self::Audio=>"Audio",Self::Image=>"Image",
                     Self::Document=>"Document",Self::Raw=>"Raw",
                     Self::Executable=>"Executable",Self::Archive=>"Archive",Self::Video=>"Video" }
    }
    pub fn is_media(&self) -> bool { matches!(self,Self::Audio|Self::Image|Self::Video) }
    pub fn detect(d: &[u8]) -> Self {
        if d.len() < 4 { return Self::Raw; }
        if d.starts_with(&[0x89,0x50,0x4E,0x47]) { return Self::Image; }
        if d.starts_with(&[0xFF,0xD8,0xFF]) { return Self::Image; }
        if d.starts_with(b"GIF8") { return Self::Image; }
        if d.starts_with(b"BM") { return Self::Image; }
        if d.starts_with(&[0x1A,0x45,0xDF,0xA3]) { return Self::Video; }
        if d.len()>=12 && &d[4..8]==b"ftyp" { return Self::Video; }
        if d.starts_with(b"ID3") { return Self::Audio; }
        if d.starts_with(b"OggS") { return Self::Audio; }
        if d.starts_with(b"fLaC") { return Self::Audio; }
        if d.len()>=2 && d[0]==0xFF && (d[1]&0xE0)==0xE0 { return Self::Audio; }
        if d.starts_with(b"%PDF") { return Self::Document; }
        if d.starts_with(&[0x50,0x4B,0x03,0x04]) { return Self::Archive; }
        if d.starts_with(&[0x1F,0x8B]) { return Self::Archive; }
        if d.starts_with(b"MZ") { return Self::Executable; }
        if d.starts_with(&[0x7F,b'E',b'L',b'F']) { return Self::Executable; }
        if likely_text(d) { return Self::Text; }
        Self::Raw
    }
}

fn likely_text(d: &[u8]) -> bool {
    let n = d.len().min(2048);
    if n == 0 { return false; }
    let p = d[..n].iter().filter(|&&b| (0x20..0x7F).contains(&b)||b==b'\n'||b==b'\r'||b==b'\t'||b>=0x80).count();
    p * 100 / n >= 90
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionKind { AeroPack = 0 }
impl CompressionKind {
    pub fn from_byte(_b: u8) -> Self { Self::AeroPack }
    pub fn label(&self) -> &'static str { "AeroPack v20" }
}

pub fn now_unix() -> u32 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    { 0 }
}

pub fn fmt_unix(ts: u32) -> String {
    let s = ts as u64;
    let days = s / 86400; let rem = s % 86400;
    let h = rem / 3600; let m = (rem % 3600) / 60;
    let mut y = 1970i64; let mut d = days as i64;
    loop {
        let leap = (y%4==0 && y%100!=0) || y%400==0;
        let diy = if leap { 366 } else { 365 };
        if d < diy { break; } d -= diy; y += 1;
    }
    let leap = (y%4==0 && y%100!=0) || y%400==0;
    let ml: [i64;12] = [31,if leap {29} else {28},31,30,31,30,31,31,30,31,30,31];
    let mut mo = 0i64;
    for i in 0..12 { if d < ml[i] { mo = i as i64 + 1; break; } d -= ml[i]; }
    if mo == 0 { mo = 12; }
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, mo, d + 1, h, m)
}

#[derive(Debug, Clone)]
pub struct AeroHeader {
    pub data_type: DataType,
    pub compression: CompressionKind,
    pub cipher: crate::crypto::CipherKind,
    pub flags: u8,
    pub original_size: u32,
    pub payload_size: u32,
    pub checksum: u16,
    pub page_index: u16,
    pub page_total: u16,
    pub content_hash: [u8; 8],
    pub signature: [u8; 64],
    pub hmac: [u8; 16],
    pub reserved: [u8; 4],
    pub page_crc: u32,
    pub resilience_level: u8,
    pub mask: u8,
}

impl AeroHeader {
    pub fn new(dt: DataType, ck: CompressionKind, ci: crate::crypto::CipherKind,
               flags: u8, os: u32, ps: u32, ch: [u8; 8]) -> Self {
        Self::with_page(dt, ck, ci, flags, os, ps, 0, 1, ch)
    }
    pub fn with_page(dt: DataType, ck: CompressionKind, ci: crate::crypto::CipherKind,
                     flags: u8, os: u32, ps: u32, pi: u16, pt: u16, ch: [u8; 8]) -> Self {
        let mut h = Self {
            data_type: dt, compression: ck, cipher: ci, flags,
            original_size: os, payload_size: ps, checksum: 0,
            page_index: pi, page_total: pt, content_hash: ch,
            signature: [0u8; 64], hmac: [0u8; 16], reserved: [0u8; 4],
            page_crc: 0, resilience_level: 0, mask: 0,
        };
        // Fixed timestamp for deterministic encoding: 1751328000 = 2025-07-01 00:00 UTC.
        // Same input bytes always produce same output pattern.
        let ts: u32 = 1751328000;
        h.reserved.copy_from_slice(&ts.to_le_bytes());
        h.checksum = h.compute_checksum();
        h
    }
    pub fn compute_checksum(&self) -> u16 {
        let mut b = [0u8; 22];
        b[0] = self.data_type as u8;
        b[1] = self.compression as u8;
        b[2] = self.cipher as u8;
        b[3] = self.flags;
        b[4..8].copy_from_slice(&self.original_size.to_le_bytes());
        b[8..12].copy_from_slice(&self.payload_size.to_le_bytes());
        b[12..14].copy_from_slice(&self.page_index.to_le_bytes());
        b[14..16].copy_from_slice(&self.page_total.to_le_bytes());
        b[16..22].copy_from_slice(&self.content_hash[..6]);
        fnv16(&b)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; AERO_HEADER_SIZE];
        b[0..3].copy_from_slice(&AERO_MAGIC);
        b[3] = AERO_VERSION;
        b[4] = self.data_type as u8;
        b[5] = self.compression as u8;
        b[6] = self.cipher as u8;
        b[7] = self.flags;
        b[8..12].copy_from_slice(&self.original_size.to_le_bytes());
        b[12..16].copy_from_slice(&self.payload_size.to_le_bytes());
        b[16..18].copy_from_slice(&self.checksum.to_le_bytes());
        b[18..20].copy_from_slice(&self.page_index.to_le_bytes());
        b[20..22].copy_from_slice(&self.page_total.to_le_bytes());
        b[22..30].copy_from_slice(&self.content_hash);
        b[30..94].copy_from_slice(&self.signature);
        b[94..110].copy_from_slice(&self.hmac);
        b[110..114].copy_from_slice(&self.reserved);
        b[114..118].copy_from_slice(&self.page_crc.to_le_bytes());
        b[118] = self.resilience_level;
        b[119] = self.mask;
        b
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < AERO_HEADER_SIZE { return None; }
        if &b[0..3] != &AERO_MAGIC { return None; }
        if b[3] != AERO_VERSION { return None; }
        let dt = DataType::from_byte(b[4]);
        let ck = CompressionKind::from_byte(b[5]);
        let ci = crate::crypto::CipherKind::from_byte(b[6]);
        let flags = b[7];
        let os = u32::from_le_bytes([b[8],b[9],b[10],b[11]]);
        let ps = u32::from_le_bytes([b[12],b[13],b[14],b[15]]);
        let cs = u16::from_le_bytes([b[16],b[17]]);
        let pi = u16::from_le_bytes([b[18],b[19]]);
        let pt = u16::from_le_bytes([b[20],b[21]]);
        let mut ch = [0u8; 8]; ch.copy_from_slice(&b[22..30]);
        let mut sig = [0u8; 64]; sig.copy_from_slice(&b[30..94]);
        let mut hmac = [0u8; 16]; hmac.copy_from_slice(&b[94..110]);
        let mut reserved = [0u8; 4]; reserved.copy_from_slice(&b[110..114]);
        let page_crc = u32::from_le_bytes([b[114], b[115], b[116], b[117]]);
        let resilience_level = b[118];
        let mask = b[119];
        let h = Self {
            data_type: dt, compression: ck, cipher: ci, flags,
            original_size: os, payload_size: ps, checksum: cs,
            page_index: pi, page_total: pt, content_hash: ch,
            signature: sig, hmac, reserved, page_crc, resilience_level, mask,
        };
        if h.compute_checksum() != cs { return None; }
        Some(h)
    }
    pub fn hmac_input(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        for i in 94..110 { b[i] = 0; }
        for i in 114..118 { b[i] = 0; }
        b
    }
    pub fn created_at(&self) -> u32 {
        u32::from_le_bytes([self.reserved[0], self.reserved[1], self.reserved[2], self.reserved[3]])
    }
    pub fn created_at_str(&self) -> String {
        let ts = self.created_at();
        if ts == 0 { return "unknown".into(); }
        fmt_unix(ts)
    }
}

pub fn fnv32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811C9DC5;
    for &b in data { h ^= b as u32; h = h.wrapping_mul(0x01000193); }
    h
}

pub fn fnv16(data: &[u8]) -> u16 {
    let mut h: u32 = 0x811C9DC5;
    for &b in data { h ^= b as u32; h = h.wrapping_mul(0x01000193); }
    ((h >> 16) ^ (h & 0xFFFF)) as u16
}


/// Format byte count as human-readable: 123 B, 4.5 KB, 1.2 MB etc.
pub fn human_bytes(b: usize) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut x = b as f64;
    let mut i = 0usize;
    while x >= 1024.0 && i < U.len() - 1 {
        x /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", b, U[0])
    } else {
        format!("{:.2} {}", x, U[i])
    }
}