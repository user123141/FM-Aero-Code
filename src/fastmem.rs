//! Fast Memory utilities - the "FM" in FM Aero Code.
//!
//! Small helpers for pre-sized buffers, atomic writes, and size caps.

use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{Read, Write, BufWriter};
use std::path::Path;

/// Read an entire file with a pre-sized buffer.
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

/// Atomic write: temp file then rename.
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

/// Reject inputs larger than a caller-provided cap.
pub fn assert_size(declared: usize, limit: usize) -> Result<()> {
    if declared > limit {
        return Err(anyhow!("declared {} > cap {}", declared, limit));
    }
    Ok(())
}