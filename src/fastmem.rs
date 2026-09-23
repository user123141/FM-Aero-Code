//! Fast Memory (FM) - the "FM" in FM Aero Code.
//!
//! Techniques used here to keep peak memory flat and allocations rare:
//!   1. BufferPool - reuse Vec<u8> allocations across the pipeline.
//!   2. read_file / write_file - single syscall, pre-sized.
//!   3. ChunkReader - iterate over chunks without loading whole file.
//!   4. assert_size - reject inputs larger than a caller-provided cap.
//!
//! No unsafe code. All operations are fallible with anyhow::Result.

use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use std::sync::Mutex;

/// Thread-safe pool of reusable byte buffers.
pub struct BufferPool {
    inner: Mutex<Vec<Vec<u8>>>,
    capacity: usize,
    max_kept: usize,
}

impl BufferPool {
    pub fn new(capacity: usize, max_kept: usize) -> Self {
        Self { inner: Mutex::new(Vec::with_capacity(max_kept)), capacity, max_kept }
    }

    /// Take a buffer from the pool, cleared and pre-sized to capacity.
    pub fn take(&self) -> Vec<u8> {
        let mut g = self.inner.lock().expect("pool poisoned");
        let mut v = g.pop().unwrap_or_else(|| Vec::with_capacity(self.capacity));
        v.clear();
        if v.capacity() < self.capacity {
            v.reserve(self.capacity - v.capacity());
        }
        v
    }

    /// Return a buffer to the pool. Oversized buffers are dropped.
    pub fn give(&self, mut v: Vec<u8>) {
        if v.capacity() > self.capacity * 4 { return; }
        v.clear();
        let mut g = self.inner.lock().expect("pool poisoned");
        if g.len() < self.max_kept {
            g.push(v);
        }
    }
}

/// Read an entire file with a pre-sized buffer (one syscall in the common case).
pub fn read_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let md = std::fs::metadata(path)?;
    let n = md.len() as usize;
    if n > max_bytes {
        return Err(anyhow!("file {} bytes > cap {}", n, max_bytes));
    }
    let mut f = File::open(path)?;
    let mut buf = Vec::with_capacity(n);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Atomic-ish write: write to temp, then rename.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp_fm2");
    {
        let f = File::create(&tmp)?;
        let mut w = BufWriter::with_capacity(64 * 1024, f);
        w.write_all(bytes)?;
        w.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Iterator over fixed-size chunks of a reader.
pub struct ChunkReader<R: Read> {
    inner: BufReader<R>,
    buf: Vec<u8>,
    done: bool,
}

impl<R: Read> ChunkReader<R> {
    pub fn new(reader: R, chunk_size: usize) -> Self {
        Self {
            inner: BufReader::with_capacity(chunk_size * 2, reader),
            buf: vec![0u8; chunk_size],
            done: false,
        }
    }
}

impl<R: Read> Iterator for ChunkReader<R> {
    type Item = Result<Vec<u8>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done { return None; }
        let mut filled = 0usize;
        loop {
            match self.inner.read(&mut self.buf[filled..]) {
                Ok(0) => {
                    self.done = true;
                    if filled == 0 { return None; }
                    let mut out = Vec::with_capacity(filled);
                    out.extend_from_slice(&self.buf[..filled]);
                    return Some(Ok(out));
                }
                Ok(n) => {
                    filled += n;
                    if filled == self.buf.len() { break; }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(anyhow!("chunk read: {}", e)));
                }
            }
        }
        let mut out = Vec::with_capacity(filled);
        out.extend_from_slice(&self.buf[..filled]);
        Some(Ok(out))
    }
}

/// Guard a declared size against a hard cap (used for decompression bombs).
pub fn assert_size(declared: usize, limit: usize) -> Result<()> {
    if declared > limit {
        return Err(anyhow!("declared {} > cap {}", declared, limit));
    }
    Ok(())
}