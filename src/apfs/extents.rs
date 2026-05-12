//! Streaming reader over a file's extent list
use std::io::{Read, Seek, SeekFrom, Write};

use crate::apfs::catalog::FileExtentVal;
use crate::apfs::error::Result;

/// Resolved extent: `(logical_start, physical_start, length_bytes)`
type ExtentSpan = (u64, u64, u64);

/// Translate the on-disk extent list into a flat `(log, phys, len)` map
fn build_extent_map(block_size: u32, extents: &[FileExtentVal]) -> Vec<ExtentSpan> {
    let bs = block_size as u64;
    let mut map = Vec::with_capacity(extents.len());
    let mut log = 0u64;
    for ext in extents {
        let len = ext.length();
        if len == 0 {
            continue;
        }
        let phys = ext.phys_block_num * bs;
        map.push((log, phys, len));
        log += len;
    }
    map
}

/// Stream a file's contents to `out`. Returns the number of bytes copied
pub fn read_file_data<R: Read + Seek, W: Write>(
    reader: &mut R,
    block_size: u32,
    extents: &[FileExtentVal],
    logical_size: u64,
    out: &mut W,
) -> Result<u64> {
    if logical_size == 0 {
        return Ok(0);
    }
    let map = build_extent_map(block_size, extents);
    let mut buf = vec![0u8; block_size as usize];
    let mut written = 0u64;

    'outer: for (_log, phys, len) in &map {
        let mut off = 0u64;
        while off < *len {
            if written >= logical_size {
                break 'outer;
            }
            let chunk = (*len - off)
                .min(logical_size - written)
                .min(block_size as u64) as usize;
            reader.seek(SeekFrom::Start(*phys + off))?;
            reader.read_exact(&mut buf[..chunk])?;
            out.write_all(&buf[..chunk])?;
            written += chunk as u64;
            off += chunk as u64;
        }
    }
    Ok(written)
}

/// `Read + Seek` adapter that exposes a file's extents as a contiguous fork
pub struct ApfsForkReader<'a, R: Read + Seek> {
    reader: &'a mut R,
    logical_size: u64,
    extent_map: Vec<ExtentSpan>,
    position: u64,
}

impl<'a, R: Read + Seek> ApfsForkReader<'a, R> {
    pub fn new(
        reader: &'a mut R,
        block_size: u32,
        extents: Vec<FileExtentVal>,
        logical_size: u64,
    ) -> Self {
        Self {
            reader,
            logical_size,
            extent_map: build_extent_map(block_size, &extents),
            position: 0,
        }
    }

    /// Translate `logical` to the physical byte offset and the number of
    /// contiguous bytes that follow inside the same on-disk extent
    fn translate(&self, logical: u64) -> Option<(u64, u64)> {
        for (lstart, pstart, len) in &self.extent_map {
            if logical >= *lstart && logical < *lstart + *len {
                let delta = logical - *lstart;
                return Some((*pstart + delta, *len - delta));
            }
        }
        None
    }
}

impl<R: Read + Seek> Read for ApfsForkReader<'_, R> {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.logical_size {
            return Ok(0);
        }
        let remaining = (self.logical_size - self.position) as usize;
        let want = dst.len().min(remaining);
        if want == 0 {
            return Ok(0);
        }
        let mut copied = 0usize;
        while copied < want {
            let here = self.position + copied as u64;
            let (phys, run) = self.translate(here).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "logical offset beyond extent map",
                )
            })?;
            let chunk = ((want - copied) as u64).min(run) as usize;
            self.reader.seek(SeekFrom::Start(phys))?;
            self.reader.read_exact(&mut dst[copied..copied + chunk])?;
            copied += chunk;
        }
        self.position += copied as u64;
        Ok(copied)
    }
}

impl<R: Read + Seek> Seek for ApfsForkReader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.position as i64 + o,
            SeekFrom::End(o) => self.logical_size as i64 + o,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of file",
            ));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_extent(length: u64, phys_block: u64) -> FileExtentVal {
        FileExtentVal::from_length_and_flags(length, 0, phys_block, 0)
    }

    #[test]
    fn map_skips_zero_length_extents() {
        let exts = vec![
            synthetic_extent(0x1000, 10),
            synthetic_extent(0, 999),
            synthetic_extent(0x800, 20),
        ];
        let map = build_extent_map(0x1000, &exts);
        assert_eq!(map.len(), 2);
        assert_eq!(map[0], (0, 10 * 0x1000, 0x1000));
        assert_eq!(map[1], (0x1000, 20 * 0x1000, 0x800));
    }

    #[test]
    fn read_file_data_streams_in_order() {
        // Build a 4 KiB "disk" of one block of 0x55s, one block of 0xAAs
        let block_size = 0x100u32;
        let mut disk = vec![0u8; (block_size as usize) * 4];
        for b in &mut disk[block_size as usize..(2 * block_size as usize)] {
            *b = 0x55;
        }
        for b in &mut disk[2 * block_size as usize..(3 * block_size as usize)] {
            *b = 0xAA;
        }
        let exts = vec![synthetic_extent(block_size as u64, 1), synthetic_extent(block_size as u64, 2)];
        let mut cursor = std::io::Cursor::new(disk);
        let mut out = Vec::new();
        let n = read_file_data(&mut cursor, block_size, &exts, 2 * block_size as u64, &mut out).unwrap();
        assert_eq!(n, 2 * block_size as u64);
        assert!(out[..block_size as usize].iter().all(|b| *b == 0x55));
        assert!(out[block_size as usize..].iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn fork_reader_seek_and_read() {
        let block_size = 0x100u32;
        let mut disk = vec![0u8; (block_size as usize) * 4];
        for (i, b) in disk[block_size as usize..(2 * block_size as usize)]
            .iter_mut()
            .enumerate()
        {
            *b = i as u8;
        }
        let exts = vec![synthetic_extent(block_size as u64, 1)];
        let mut cursor = std::io::Cursor::new(disk);
        let mut fork = ApfsForkReader::new(&mut cursor, block_size, exts, block_size as u64);
        fork.seek(SeekFrom::Start(16)).unwrap();
        let mut buf = [0u8; 4];
        fork.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [16u8, 17, 18, 19]);
    }
}
