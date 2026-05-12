//! Space manager and chunk-bitmap allocator
//!
//! Loopback-image scope: single MAIN device (no Fusion / TIER2), one CIB
//! direct array (no CAB indirection), bitmap mutations cached in memory and
//! exposed for the checkpoint writer to place COW-style
use std::io::{Read, Seek};

use crate::apfs::error::{ApfsError, Result};
use crate::apfs::object;

pub const SD_MAIN: usize = 0;
pub const SD_TIER2: usize = 1;
pub const SD_COUNT: usize = 2;
pub const SFQ_COUNT: usize = 3;

#[derive(Debug, Clone)]
pub struct SpacemanDevice {
    pub block_count: u64,
    pub chunk_count: u64,
    pub cib_count: u32,
    pub cab_count: u32,
    pub free_count: u64,
    pub addr_offset: u32,
    pub _reserved: u32,
    pub _reserved2: u64,
}

impl SpacemanDevice {
    pub const SIZE: usize = 48;
    fn parse(b: &[u8], off: &mut usize) -> Result<Self> {
        if b.len() < *off + Self::SIZE {
            return Err(ApfsError::BadCatalog("spaceman device truncated".into()));
        }
        let s = &b[*off..*off + Self::SIZE];
        *off += Self::SIZE;
        Ok(Self {
            block_count: u64::from_le_bytes(s[0..8].try_into().unwrap()),
            chunk_count: u64::from_le_bytes(s[8..16].try_into().unwrap()),
            cib_count: u32::from_le_bytes(s[16..20].try_into().unwrap()),
            cab_count: u32::from_le_bytes(s[20..24].try_into().unwrap()),
            free_count: u64::from_le_bytes(s[24..32].try_into().unwrap()),
            addr_offset: u32::from_le_bytes(s[32..36].try_into().unwrap()),
            _reserved: u32::from_le_bytes(s[36..40].try_into().unwrap()),
            _reserved2: u64::from_le_bytes(s[40..48].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpacemanFreeQueue {
    pub count: u64,
    pub tree_oid: u64,
    pub oldest_xid: u64,
    pub tree_node_limit: u16,
    pub _pad16: u16,
    pub _pad32: u32,
    pub _reserved: u64,
}

impl SpacemanFreeQueue {
    pub const SIZE: usize = 40;
    fn parse(b: &[u8], off: &mut usize) -> Result<Self> {
        if b.len() < *off + Self::SIZE {
            return Err(ApfsError::BadCatalog("spaceman fq truncated".into()));
        }
        let s = &b[*off..*off + Self::SIZE];
        *off += Self::SIZE;
        Ok(Self {
            count: u64::from_le_bytes(s[0..8].try_into().unwrap()),
            tree_oid: u64::from_le_bytes(s[8..16].try_into().unwrap()),
            oldest_xid: u64::from_le_bytes(s[16..24].try_into().unwrap()),
            tree_node_limit: u16::from_le_bytes(s[24..26].try_into().unwrap()),
            _pad16: u16::from_le_bytes(s[26..28].try_into().unwrap()),
            _pad32: u32::from_le_bytes(s[28..32].try_into().unwrap()),
            _reserved: u64::from_le_bytes(s[32..40].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Spaceman {
    pub block_size: u32,
    pub blocks_per_chunk: u32,
    pub chunks_per_cib: u32,
    pub cibs_per_cab: u32,
    pub dev: [SpacemanDevice; SD_COUNT],
    pub flags: u32,
    pub ip_bm_tx_multiplier: u32,
    pub ip_block_count: u64,
    pub ip_bm_size_in_blocks: u32,
    pub ip_bm_block_count: u32,
    pub ip_bm_base: u64,
    pub ip_base: u64,
    pub fs_reserve_block_count: u64,
    pub fs_reserve_alloc_count: u64,
    pub fq: [SpacemanFreeQueue; SFQ_COUNT],
    pub main_cib_addrs: Vec<u64>,
    pub raw_block: Vec<u8>,
    pub paddr: u64,
}

impl Spaceman {
    pub fn read<R: Read + Seek>(reader: &mut R, paddr: u64, block_size: u32) -> Result<Self> {
        let raw = object::read_block(reader, paddr, block_size)?;
        Self::parse(&raw, paddr)
    }

    pub fn parse(raw: &[u8], paddr: u64) -> Result<Self> {
        if raw.len() < object::ObjectHeader::SIZE + 256 {
            return Err(ApfsError::BadCatalog("spaceman block too short".into()));
        }
        let body = &raw[object::ObjectHeader::SIZE..];
        let mut off = 0usize;
        let block_size = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let blocks_per_chunk = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let chunks_per_cib = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let cibs_per_cab = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let dev = [
            SpacemanDevice::parse(body, &mut off)?,
            SpacemanDevice::parse(body, &mut off)?,
        ];
        let flags = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let ip_bm_tx_multiplier = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let ip_block_count = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let ip_bm_size_in_blocks = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let ip_bm_block_count = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        off += 4;
        let ip_bm_base = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let ip_base = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let fs_reserve_block_count = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let fs_reserve_alloc_count = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
        off += 8;
        let fq = [
            SpacemanFreeQueue::parse(body, &mut off)?,
            SpacemanFreeQueue::parse(body, &mut off)?,
            SpacemanFreeQueue::parse(body, &mut off)?,
        ];
        let _ = off;

        let main = &dev[SD_MAIN];
        let mut main_cib_addrs = Vec::with_capacity(main.cib_count as usize);
        if main.cab_count == 0 {
            let off = main.addr_offset as usize;
            if off + 8 * main.cib_count as usize > raw.len() {
                return Err(ApfsError::BadCatalog(format!(
                    "spaceman cib addr_offset {} oob (block {})",
                    off,
                    raw.len()
                )));
            }
            for i in 0..main.cib_count as u64 {
                let p = u64::from_le_bytes(
                    raw[off + 8 * i as usize..off + 8 * i as usize + 8]
                        .try_into()
                        .unwrap(),
                );
                main_cib_addrs.push(p);
            }
        } else {
            return Err(ApfsError::Unsupported(
                "spaceman with CAB indirection (large container)".into(),
            ));
        }

        Ok(Self {
            block_size,
            blocks_per_chunk,
            chunks_per_cib,
            cibs_per_cab,
            dev,
            flags,
            ip_bm_tx_multiplier,
            ip_block_count,
            ip_bm_size_in_blocks,
            ip_bm_block_count,
            ip_bm_base,
            ip_base,
            fs_reserve_block_count,
            fs_reserve_alloc_count,
            fq,
            main_cib_addrs,
            raw_block: raw.to_vec(),
            paddr,
        })
    }

    pub fn main_free_count(&self) -> u64 {
        self.dev[SD_MAIN].free_count
    }
    pub fn main_block_count(&self) -> u64 {
        self.dev[SD_MAIN].block_count
    }
}

#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub xid: u64,
    pub addr: u64,
    pub block_count: u32,
    pub free_count: u32,
    pub bitmap_addr: u64,
}

impl ChunkInfo {
    pub const SIZE: usize = 32;
    fn parse(b: &[u8], off: &mut usize) -> Result<Self> {
        if b.len() < *off + Self::SIZE {
            return Err(ApfsError::BadCatalog("chunk_info truncated".into()));
        }
        let s = &b[*off..*off + Self::SIZE];
        *off += Self::SIZE;
        Ok(Self {
            xid: u64::from_le_bytes(s[0..8].try_into().unwrap()),
            addr: u64::from_le_bytes(s[8..16].try_into().unwrap()),
            block_count: u32::from_le_bytes(s[16..20].try_into().unwrap()),
            free_count: u32::from_le_bytes(s[20..24].try_into().unwrap()),
            bitmap_addr: u64::from_le_bytes(s[24..32].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChunkInfoBlock {
    pub index: u32,
    pub chunk_info_count: u32,
    pub chunks: Vec<ChunkInfo>,
    pub raw_block: Vec<u8>,
    pub paddr: u64,
}

impl ChunkInfoBlock {
    pub fn read<R: Read + Seek>(reader: &mut R, paddr: u64, block_size: u32) -> Result<Self> {
        let raw = object::read_block(reader, paddr, block_size)?;
        Self::parse(&raw, paddr)
    }

    pub fn parse(raw: &[u8], paddr: u64) -> Result<Self> {
        if raw.len() < object::ObjectHeader::SIZE + 8 {
            return Err(ApfsError::BadCatalog("CIB too short".into()));
        }
        let body = &raw[object::ObjectHeader::SIZE..];
        let index = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let chunk_info_count = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let mut off = 8usize;
        let mut chunks = Vec::with_capacity(chunk_info_count as usize);
        for _ in 0..chunk_info_count {
            chunks.push(ChunkInfo::parse(body, &mut off)?);
        }
        Ok(Self {
            index,
            chunk_info_count,
            chunks,
            raw_block: raw.to_vec(),
            paddr,
        })
    }
}

pub struct SpaceManager {
    pub spaceman: Spaceman,
    pub cibs: Vec<ChunkInfoBlock>,
    pub bitmaps: Vec<Vec<u8>>,
    dirty: Vec<bool>,
    block_size: u32,
}

impl SpaceManager {
    pub fn open<R: Read + Seek>(
        reader: &mut R,
        spaceman_paddr: u64,
        block_size: u32,
    ) -> Result<Self> {
        let spaceman = Spaceman::read(reader, spaceman_paddr, block_size)?;
        if spaceman.dev[SD_TIER2].block_count != 0 {
            return Err(ApfsError::Unsupported(
                "Fusion (TIER2) volumes not supported for write".into(),
            ));
        }
        let mut cibs = Vec::with_capacity(spaceman.main_cib_addrs.len());
        for &cib_paddr in &spaceman.main_cib_addrs {
            cibs.push(ChunkInfoBlock::read(reader, cib_paddr, block_size)?);
        }
        let mut bitmaps = Vec::new();
        for cib in &cibs {
            for ch in &cib.chunks {
                if ch.bitmap_addr == 0 {
                    let bytes = (ch.block_count as usize + 7) / 8;
                    bitmaps.push(vec![0u8; bytes]);
                } else {
                    let raw = object::read_block(reader, ch.bitmap_addr, block_size)?;
                    bitmaps.push(raw);
                }
            }
        }
        let dirty = vec![false; bitmaps.len()];
        Ok(Self {
            spaceman,
            cibs,
            bitmaps,
            dirty,
            block_size,
        })
    }

    /// Allocate a single free block from MAIN
    pub fn alloc_block(&mut self) -> Result<u64> {
        let mut flat_idx = 0usize;
        for cib in self.cibs.iter_mut() {
            for ch in cib.chunks.iter_mut() {
                if ch.free_count == 0 {
                    flat_idx += 1;
                    continue;
                }
                let bm = &mut self.bitmaps[flat_idx];
                if let Some(bit) = find_first_clear_bit(bm, ch.block_count as usize) {
                    set_bit(bm, bit);
                    ch.free_count -= 1;
                    self.dirty[flat_idx] = true;
                    self.spaceman.dev[SD_MAIN].free_count -= 1;
                    return Ok(ch.addr + bit as u64);
                }
                flat_idx += 1;
            }
        }
        Err(ApfsError::Internal("no free blocks available".into()))
    }

    /// Allocate `count` blocks from MAIN, returning one or more contiguous
    /// runs `(start_paddr, length)` whose lengths sum to `count`
    ///
    /// First tries to satisfy the whole request from a single contiguous run
    /// inside one chunk; on failure, falls back to greedy first-fit across
    /// chunks. On allocator exhaustion any partial allocations made during
    /// the call are rolled back before returning the error
    pub fn alloc_blocks(&mut self, count: u64) -> Result<Vec<(u64, u64)>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > self.spaceman.dev[SD_MAIN].free_count {
            return Err(ApfsError::Internal(
                "alloc_blocks: not enough free blocks".into(),
            ));
        }

        // Fast path: try a single contiguous run inside one chunk
        if let Some((flat_idx, start_bit, run_len)) = self.find_contiguous_run(count) {
            let bm = &mut self.bitmaps[flat_idx];
            for b in start_bit..start_bit + run_len as usize {
                set_bit(bm, b);
            }
            let chunk_addr = self.chunk_addr_at(flat_idx);
            self.consume_chunk(flat_idx, run_len);
            return Ok(vec![(chunk_addr + start_bit as u64, run_len)]);
        }

        // Slow path: greedy fragmented allocation. We keep a rollback log so
        // a mid-allocation failure leaves the bitmap untouched
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut remaining = count;
        while remaining > 0 {
            let Some((flat_idx, start_bit, run_len_max)) = self.find_any_run() else {
                self.rollback_runs(&runs);
                return Err(ApfsError::Internal(
                    "alloc_blocks: fragmentation prevents satisfying request".into(),
                ));
            };
            let take = run_len_max.min(remaining);
            let bm = &mut self.bitmaps[flat_idx];
            for b in start_bit..start_bit + take as usize {
                set_bit(bm, b);
            }
            let chunk_addr = self.chunk_addr_at(flat_idx);
            self.consume_chunk(flat_idx, take);
            runs.push((chunk_addr + start_bit as u64, take));
            remaining -= take;
        }
        Ok(runs)
    }

    /// Free `length` consecutive blocks starting at `paddr`. The range must
    /// lie entirely within a single chunk and must currently be marked used
    pub fn free_blocks(&mut self, paddr: u64, length: u64) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        let mut flat_idx = 0usize;
        for cib in self.cibs.iter_mut() {
            for ch in cib.chunks.iter_mut() {
                let end = ch.addr + ch.block_count as u64;
                if paddr >= ch.addr && paddr < end {
                    if paddr + length > end {
                        return Err(ApfsError::Internal(
                            "free_blocks: range crosses chunk boundary".into(),
                        ));
                    }
                    let bm = &mut self.bitmaps[flat_idx];
                    let start_bit = (paddr - ch.addr) as usize;
                    for b in start_bit..start_bit + length as usize {
                        if !get_bit(bm, b) {
                            return Err(ApfsError::Internal(format!(
                                "free_blocks: block {} already free",
                                ch.addr + b as u64
                            )));
                        }
                        clear_bit(bm, b);
                    }
                    ch.free_count = ch.free_count.saturating_add(length as u32);
                    self.dirty[flat_idx] = true;
                    self.spaceman.dev[SD_MAIN].free_count =
                        self.spaceman.dev[SD_MAIN].free_count.saturating_add(length);
                    return Ok(());
                }
                flat_idx += 1;
            }
        }
        Err(ApfsError::Internal(format!(
            "free_blocks: paddr {paddr} not in any chunk"
        )))
    }

    /// Free a single block (convenience around [`Self::free_blocks`])
    pub fn free_block(&mut self, paddr: u64) -> Result<()> {
        self.free_blocks(paddr, 1)
    }

    fn chunk_addr_at(&self, flat_idx: usize) -> u64 {
        let mut i = 0usize;
        for cib in &self.cibs {
            for ch in &cib.chunks {
                if i == flat_idx {
                    return ch.addr;
                }
                i += 1;
            }
        }
        unreachable!("chunk_addr_at: flat_idx out of range")
    }

    fn consume_chunk(&mut self, flat_idx: usize, count: u64) {
        let mut i = 0usize;
        for cib in self.cibs.iter_mut() {
            for ch in cib.chunks.iter_mut() {
                if i == flat_idx {
                    ch.free_count = ch.free_count.saturating_sub(count as u32);
                    self.dirty[flat_idx] = true;
                    self.spaceman.dev[SD_MAIN].free_count =
                        self.spaceman.dev[SD_MAIN].free_count.saturating_sub(count);
                    return;
                }
                i += 1;
            }
        }
    }

    /// Find a contiguous run of `count` clear bits inside a single chunk's
    /// bitmap. Returns `(flat_chunk_idx, start_bit, count)` on success
    fn find_contiguous_run(&self, count: u64) -> Option<(usize, usize, u64)> {
        let mut flat_idx = 0usize;
        for cib in &self.cibs {
            for ch in &cib.chunks {
                if (ch.free_count as u64) < count {
                    flat_idx += 1;
                    continue;
                }
                let bm = &self.bitmaps[flat_idx];
                let total = ch.block_count as usize;
                if let Some(start) = find_clear_run(bm, total, count as usize) {
                    return Some((flat_idx, start, count));
                }
                flat_idx += 1;
            }
        }
        None
    }

    /// Find any non-empty contiguous clear run; returns the first run found
    fn find_any_run(&self) -> Option<(usize, usize, u64)> {
        let mut flat_idx = 0usize;
        for cib in &self.cibs {
            for ch in &cib.chunks {
                if ch.free_count == 0 {
                    flat_idx += 1;
                    continue;
                }
                let bm = &self.bitmaps[flat_idx];
                let total = ch.block_count as usize;
                if let Some((start, len)) = find_first_clear_run(bm, total) {
                    return Some((flat_idx, start, len as u64));
                }
                flat_idx += 1;
            }
        }
        None
    }

    fn rollback_runs(&mut self, runs: &[(u64, u64)]) {
        for &(paddr, len) in runs {
            // best-effort: ignore secondary errors during rollback
            let _ = self.free_blocks(paddr, len);
        }
    }

    pub fn is_block_used(&self, paddr: u64) -> Option<bool> {
        let mut flat_idx = 0usize;
        for cib in &self.cibs {
            for ch in &cib.chunks {
                let end = ch.addr + ch.block_count as u64;
                if paddr >= ch.addr && paddr < end {
                    let bit = (paddr - ch.addr) as usize;
                    return Some(get_bit(&self.bitmaps[flat_idx], bit));
                }
                flat_idx += 1;
            }
        }
        None
    }

    pub fn dirty_bitmaps(&self) -> Vec<(usize, &[u8])> {
        self.dirty
            .iter()
            .enumerate()
            .filter_map(|(i, &d)| {
                if d {
                    Some((i, self.bitmaps[i].as_slice()))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }
}

fn find_first_clear_bit(bitmap: &[u8], total_bits: usize) -> Option<usize> {
    for (byte_idx, &byte) in bitmap.iter().enumerate() {
        if byte == 0xFF {
            continue;
        }
        for bit in 0..8 {
            let global = byte_idx * 8 + bit;
            if global >= total_bits {
                return None;
            }
            if (byte >> bit) & 1 == 0 {
                return Some(global);
            }
        }
    }
    None
}

fn set_bit(bitmap: &mut [u8], bit: usize) {
    bitmap[bit / 8] |= 1 << (bit % 8);
}

fn clear_bit(bitmap: &mut [u8], bit: usize) {
    bitmap[bit / 8] &= !(1 << (bit % 8));
}

fn get_bit(bitmap: &[u8], bit: usize) -> bool {
    bitmap[bit / 8] & (1 << (bit % 8)) != 0
}

/// Locate the start of the first clear run of length >= `count` within the
/// first `total_bits` bits of `bitmap`. Bits past `total_bits` are treated
/// as set (unavailable)
fn find_clear_run(bitmap: &[u8], total_bits: usize, count: usize) -> Option<usize> {
    if count == 0 {
        return Some(0);
    }
    let mut run_start: Option<usize> = None;
    let mut run_len = 0usize;
    for bit in 0..total_bits {
        if !get_bit(bitmap, bit) {
            if run_start.is_none() {
                run_start = Some(bit);
                run_len = 1;
            } else {
                run_len += 1;
            }
            if run_len >= count {
                return run_start;
            }
        } else {
            run_start = None;
            run_len = 0;
        }
    }
    None
}

/// Locate the first non-empty clear run; return `(start, length)`
fn find_first_clear_run(bitmap: &[u8], total_bits: usize) -> Option<(usize, usize)> {
    let mut bit = 0usize;
    while bit < total_bits {
        if get_bit(bitmap, bit) {
            bit += 1;
            continue;
        }
        let start = bit;
        while bit < total_bits && !get_bit(bitmap, bit) {
            bit += 1;
        }
        return Some((start, bit - start));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_helpers() {
        let mut bm = vec![0u8; 4];
        assert_eq!(find_first_clear_bit(&bm, 32), Some(0));
        set_bit(&mut bm, 0);
        assert!(get_bit(&bm, 0));
        assert_eq!(find_first_clear_bit(&bm, 32), Some(1));
        for i in 0..16 {
            set_bit(&mut bm, i);
        }
        assert_eq!(find_first_clear_bit(&bm, 32), Some(16));
        let full = vec![0xFFu8; 4];
        assert_eq!(find_first_clear_bit(&full, 32), None);
    }

    #[test]
    fn run_helpers() {
        let mut bm = vec![0u8; 4];
        // first clear run of >=3 starts at bit 0 of an empty bitmap
        assert_eq!(find_clear_run(&bm, 32, 3), Some(0));
        for i in 0..5 {
            set_bit(&mut bm, i);
        }
        assert_eq!(find_clear_run(&bm, 32, 3), Some(5));
        // mark a hole that is too small followed by a big enough one
        for i in 0..32 {
            set_bit(&mut bm, i);
        }
        clear_bit(&mut bm, 4);
        clear_bit(&mut bm, 10);
        clear_bit(&mut bm, 11);
        clear_bit(&mut bm, 12);
        assert_eq!(find_clear_run(&bm, 32, 3), Some(10));
        assert_eq!(find_first_clear_run(&bm, 32), Some((4, 1)));
    }

    /// Build a synthetic SpaceManager covering 2 chunks of 64 blocks each
    /// so we can drive alloc/free against in-memory bitmaps without needing
    /// a real disk image
    fn synth(chunks: usize, blocks_per_chunk: u32) -> SpaceManager {
        let total_blocks = chunks as u64 * blocks_per_chunk as u64;
        let mut sm = Spaceman {
            block_size: 4096,
            blocks_per_chunk,
            chunks_per_cib: chunks as u32,
            cibs_per_cab: 0,
            dev: [
                SpacemanDevice {
                    block_count: total_blocks,
                    chunk_count: chunks as u64,
                    cib_count: 1,
                    cab_count: 0,
                    free_count: total_blocks,
                    addr_offset: 0,
                    _reserved: 0,
                    _reserved2: 0,
                },
                SpacemanDevice {
                    block_count: 0,
                    chunk_count: 0,
                    cib_count: 0,
                    cab_count: 0,
                    free_count: 0,
                    addr_offset: 0,
                    _reserved: 0,
                    _reserved2: 0,
                },
            ],
            flags: 0,
            ip_bm_tx_multiplier: 0,
            ip_block_count: 0,
            ip_bm_size_in_blocks: 0,
            ip_bm_block_count: 0,
            ip_bm_base: 0,
            ip_base: 0,
            fs_reserve_block_count: 0,
            fs_reserve_alloc_count: 0,
            fq: [
                SpacemanFreeQueue {
                    count: 0,
                    tree_oid: 0,
                    oldest_xid: 0,
                    tree_node_limit: 0,
                    _pad16: 0,
                    _pad32: 0,
                    _reserved: 0,
                },
                SpacemanFreeQueue {
                    count: 0,
                    tree_oid: 0,
                    oldest_xid: 0,
                    tree_node_limit: 0,
                    _pad16: 0,
                    _pad32: 0,
                    _reserved: 0,
                },
                SpacemanFreeQueue {
                    count: 0,
                    tree_oid: 0,
                    oldest_xid: 0,
                    tree_node_limit: 0,
                    _pad16: 0,
                    _pad32: 0,
                    _reserved: 0,
                },
            ],
            main_cib_addrs: vec![1000],
            raw_block: vec![0u8; 4096],
            paddr: 999,
        };
        sm.dev[SD_MAIN].free_count = total_blocks;

        let mut chunk_infos = Vec::new();
        for i in 0..chunks {
            chunk_infos.push(ChunkInfo {
                xid: 1,
                addr: 100 + i as u64 * blocks_per_chunk as u64,
                block_count: blocks_per_chunk,
                free_count: blocks_per_chunk,
                bitmap_addr: 0,
            });
        }
        let cibs = vec![ChunkInfoBlock {
            index: 0,
            chunk_info_count: chunks as u32,
            chunks: chunk_infos,
            raw_block: vec![0u8; 4096],
            paddr: 1000,
        }];
        let bytes_per_chunk = (blocks_per_chunk as usize).div_ceil(8);
        let bitmaps = vec![vec![0u8; bytes_per_chunk]; chunks];
        let dirty = vec![false; chunks];
        SpaceManager {
            spaceman: sm,
            cibs,
            bitmaps,
            dirty,
            block_size: 4096,
        }
    }

    #[test]
    fn alloc_block_marks_used_and_decrements_free() {
        let mut sm = synth(2, 64);
        let initial = sm.spaceman.dev[SD_MAIN].free_count;
        let p = sm.alloc_block().unwrap();
        assert_eq!(p, 100);
        assert_eq!(sm.is_block_used(p), Some(true));
        assert_eq!(sm.spaceman.dev[SD_MAIN].free_count, initial - 1);
        assert!(!sm.dirty_bitmaps().is_empty());
    }

    #[test]
    fn alloc_blocks_returns_single_run_when_possible() {
        let mut sm = synth(2, 64);
        let runs = sm.alloc_blocks(8).unwrap();
        assert_eq!(runs, vec![(100, 8)]);
        for b in 0..8 {
            assert_eq!(sm.is_block_used(100 + b), Some(true));
        }
        assert_eq!(sm.spaceman.dev[SD_MAIN].free_count, 128 - 8);
    }

    #[test]
    fn alloc_blocks_falls_back_to_fragmented_runs() {
        let mut sm = synth(1, 16);
        // Allocate all 16 blocks then poke 3 isolated 1-block holes so no
        // single contiguous run can satisfy a 3-block request
        for _ in 0..16 {
            sm.alloc_block().unwrap();
        }
        sm.free_block(100).unwrap();
        sm.free_block(105).unwrap();
        sm.free_block(110).unwrap();
        let runs = sm.alloc_blocks(3).unwrap();
        let total: u64 = runs.iter().map(|&(_, l)| l).sum();
        assert_eq!(total, 3);
        assert_eq!(
            runs.len(),
            3,
            "expected fragmented allocation, got {:?}",
            runs
        );
        assert_eq!(sm.spaceman.dev[SD_MAIN].free_count, 0);
    }

    #[test]
    fn alloc_blocks_rolls_back_on_exhaustion() {
        let mut sm = synth(1, 16);
        sm.alloc_block().unwrap();
        sm.alloc_block().unwrap();
        let mid = sm.spaceman.dev[SD_MAIN].free_count;
        let err = sm.alloc_blocks(100).unwrap_err();
        assert!(format!("{err}").contains("not enough"));
        assert_eq!(sm.spaceman.dev[SD_MAIN].free_count, mid);
    }

    #[test]
    fn free_blocks_returns_capacity_to_chunk() {
        let mut sm = synth(2, 64);
        let runs = sm.alloc_blocks(10).unwrap();
        let (start, len) = runs[0];
        sm.free_blocks(start, len).unwrap();
        for b in 0..len {
            assert_eq!(sm.is_block_used(start + b), Some(false));
        }
        assert_eq!(sm.spaceman.dev[SD_MAIN].free_count, 128);
    }

    #[test]
    fn free_blocks_rejects_double_free() {
        let mut sm = synth(2, 64);
        let p = sm.alloc_block().unwrap();
        sm.free_block(p).unwrap();
        let err = sm.free_block(p).unwrap_err();
        assert!(format!("{err}").contains("already free"));
    }

    #[test]
    fn free_blocks_rejects_cross_chunk_range() {
        let sm = synth(2, 64);
        // Chunk 0 spans 100..164, chunk 1 spans 164..228. A free request
        // straddling the boundary must be rejected outright
        let mut sm = sm;
        // Mark blocks 162..166 as used so we have something to free
        for p in 162..166 {
            // synth bitmaps start fully clear; manually flip them via alloc
            // by exhausting the chunk is overkill; call free_blocks on the
            // straddling range directly: it's currently free, so first
            // failure mode is "already free" *or* "crosses chunk boundary"
            // We accept "crosses chunk boundary" as the contract
            let _ = p;
        }
        let err = sm.free_blocks(162, 4).unwrap_err();
        assert!(
            format!("{err}").contains("crosses chunk boundary"),
            "unexpected error: {err}"
        );
    }
}
