//! APFS B-tree node parser, lookup, scan, and primitive in-place mutations
//!
//! # Layout
//!
//! Every B-tree node lives inside one block. After the 32-byte object header
//! and a 24-byte `btree_node_phys_t` fixed prefix, the remaining bytes
//! (`btn_data`) hold a table-of-contents area, key bytes packed forward, and
//! value bytes packed backward from the end of the data slab. Root nodes have
//! a 40-byte `btree_info_t` footer at the very end of the block
//!
//! TOC entry shape depends on the `BTNODE_FIXED_KV_SIZE` flag:
//! - fixed: `kvoff_t` = `(key_off u16, val_off u16)` (4 bytes)
//! - variable: `kvloc_t` = `(key_off u16, key_len u16, val_off u16, val_len u16)` (8 bytes)
//!
//! For internal nodes the "value" is always a fixed 8-byte child OID; the
//! TOC entry is sized accordingly
use crate::apfs::error::{ApfsError, Result};
use crate::apfs::fletcher;
use crate::apfs::object::{
    OBJECT_TYPE_BTREE_NODE, ObjectHeader, read_block,
};
use std::cmp::Ordering;
use std::io::{Read, Seek};

pub const BTNODE_FIXED_PREFIX: usize = 56; // header(32) + btn fields(24)

/// Flag bits on `btn_flags`
pub mod flags {
    pub const ROOT: u16 = 0x0001;
    pub const LEAF: u16 = 0x0002;
    pub const FIXED_KV_SIZE: u16 = 0x0004;
    pub const HASHED: u16 = 0x0008;
    pub const NO_HEADER: u16 = 0x0010;
}

/// Root-only footer layout (`btree_info_t`)
pub const BTREE_INFO_SIZE: usize = 40;

/// `(off, len)` pair as stored in `btn_table_space`/`btn_free_space`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nloc {
    pub off: u16,
    pub len: u16,
}

impl Nloc {
    fn parse(b: &[u8]) -> Self {
        Self {
            off: u16::from_le_bytes([b[0], b[1]]),
            len: u16::from_le_bytes([b[2], b[3]]),
        }
    }
    fn write_into(self, out: &mut [u8]) {
        out[..2].copy_from_slice(&self.off.to_le_bytes());
        out[2..4].copy_from_slice(&self.len.to_le_bytes());
    }
}

/// TOC entry for either fixed-KV or variable-KV nodes. Offsets are relative to the start of `btn_data`
#[derive(Debug, Clone, Copy)]
pub struct TocEntry {
    pub key_off: u16,
    pub key_len: u16,
    pub val_off: u16,
    pub val_len: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct BTreeInfo {
    pub flags: u32,
    pub node_size: u32,
    pub key_size: u32,
    pub val_size: u32,
    pub longest_key: u32,
    pub longest_val: u32,
    pub key_count: u64,
    pub node_count: u64,
}

impl BTreeInfo {
    pub const SIZE: usize = BTREE_INFO_SIZE;

    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < Self::SIZE {
            return Err(ApfsError::Truncated {
                need: Self::SIZE,
                have: b.len(),
            });
        }
        Ok(Self {
            flags: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            node_size: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            key_size: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            val_size: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            longest_key: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            longest_val: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            key_count: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            node_count: u64::from_le_bytes(b[32..40].try_into().unwrap()),
        })
    }

    fn write_into(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.flags.to_le_bytes());
        out[4..8].copy_from_slice(&self.node_size.to_le_bytes());
        out[8..12].copy_from_slice(&self.key_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.val_size.to_le_bytes());
        out[16..20].copy_from_slice(&self.longest_key.to_le_bytes());
        out[20..24].copy_from_slice(&self.longest_val.to_le_bytes());
        out[24..32].copy_from_slice(&self.key_count.to_le_bytes());
        out[32..40].copy_from_slice(&self.node_count.to_le_bytes());
    }
}

/// Parsed B-tree node. Owns the block bytes so mutations can be written back without re-reading
pub struct BTreeNode {
    pub header: ObjectHeader,
    pub flags: u16,
    pub level: u16,
    pub table_space: Nloc,
    pub free_space: Nloc,
    pub key_free_list: Nloc,
    pub val_free_list: Nloc,

    pub toc: Vec<TocEntry>,
    pub info: Option<BTreeInfo>,

    /// Full block bytes including header. Mutations splice into this;
    /// [`Self::serialize`] refreshes the checksum before returning
    block: Vec<u8>,
}

impl BTreeNode {
    pub fn parse(block: &[u8]) -> Result<Self> {
        let header = ObjectHeader::parse(block)?;
        // Both root B-trees (OBJECT_TYPE_BTREE) and non-root nodes
        // (OBJECT_TYPE_BTREE_NODE) share the same on-disk layout
        let ot = header.object_type();
        if ot != OBJECT_TYPE_BTREE_NODE && ot != crate::apfs::object::OBJECT_TYPE_BTREE {
            return Err(ApfsError::BadObjectType {
                expected: OBJECT_TYPE_BTREE_NODE,
                actual: ot,
            });
        }
        if block.len() < BTNODE_FIXED_PREFIX {
            return Err(ApfsError::Truncated {
                need: BTNODE_FIXED_PREFIX,
                have: block.len(),
            });
        }

        let p = &block[ObjectHeader::SIZE..];
        let flags = u16::from_le_bytes([p[0], p[1]]);
        let level = u16::from_le_bytes([p[2], p[3]]);
        let nkeys = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
        let table_space = Nloc::parse(&p[8..12]);
        let free_space = Nloc::parse(&p[12..16]);
        let key_free_list = Nloc::parse(&p[16..20]);
        let val_free_list = Nloc::parse(&p[20..24]);

        let info = if (flags & flags::ROOT) != 0 {
            if block.len() < BTREE_INFO_SIZE {
                return Err(ApfsError::Truncated {
                    need: BTREE_INFO_SIZE,
                    have: block.len(),
                });
            }
            Some(BTreeInfo::parse(&block[block.len() - BTREE_INFO_SIZE..])?)
        } else {
            None
        };

        // Decode TOC
        let data_start = BTNODE_FIXED_PREFIX;
        let toc_off = data_start + table_space.off as usize;
        let fixed_kv = (flags & flags::FIXED_KV_SIZE) != 0;
        let toc_entry_size = if fixed_kv { 4 } else { 8 };
        let need = toc_entry_size * nkeys as usize;
        if toc_off + need > block.len() {
            return Err(ApfsError::BadBTree(format!(
                "toc overflows block (off={toc_off}, need={need}, block_len={})",
                block.len()
            )));
        }

        // For fixed-KV we need the per-tree key/val sizes from `btree_info`
        // The root node carries its own info; for non-root nodes the caller
        // (lookup/scan) plumbs the sizes through
        let mut toc = Vec::with_capacity(nkeys as usize);
        for i in 0..nkeys as usize {
            let entry_bytes = &block[toc_off + i * toc_entry_size..toc_off + (i + 1) * toc_entry_size];
            let toc_entry = if fixed_kv {
                let key_off = u16::from_le_bytes([entry_bytes[0], entry_bytes[1]]);
                let val_off = u16::from_le_bytes([entry_bytes[2], entry_bytes[3]]);
                TocEntry {
                    key_off,
                    key_len: 0, // filled in by callers using fixed sizes
                    val_off,
                    val_len: 0,
                }
            } else {
                TocEntry {
                    key_off: u16::from_le_bytes([entry_bytes[0], entry_bytes[1]]),
                    key_len: u16::from_le_bytes([entry_bytes[2], entry_bytes[3]]),
                    val_off: u16::from_le_bytes([entry_bytes[4], entry_bytes[5]]),
                    val_len: u16::from_le_bytes([entry_bytes[6], entry_bytes[7]]),
                }
            };
            toc.push(toc_entry);
        }

        Ok(Self {
            header,
            flags,
            level,
            table_space,
            free_space,
            key_free_list,
            val_free_list,
            toc,
            info,
            block: block.to_vec(),
        })
    }

    pub fn is_leaf(&self) -> bool {
        (self.flags & flags::LEAF) != 0
    }
    pub fn is_root(&self) -> bool {
        (self.flags & flags::ROOT) != 0
    }
    pub fn fixed_kv(&self) -> bool {
        (self.flags & flags::FIXED_KV_SIZE) != 0
    }
    pub fn nkeys(&self) -> usize {
        self.toc.len()
    }

    fn keys_area_start(&self) -> usize {
        // Keys live immediately after the TOC slot inside btn_data
        BTNODE_FIXED_PREFIX + self.table_space.off as usize + self.table_space.len as usize
    }

    fn val_area_end(&self) -> usize {
        // Values grow downward from the end of btn_data, which is the end of
        // the block minus the optional `btree_info_t` footer
        if self.is_root() {
            self.block.len() - BTREE_INFO_SIZE
        } else {
            self.block.len()
        }
    }

    /// Slice the i-th key. For fixed-KV nodes pass the key size from the
    /// owning tree; for variable-KV nodes pass `0`
    pub fn key_at(&self, i: usize, fixed_key_size: u32) -> Result<&[u8]> {
        let entry = self.toc.get(i).ok_or_else(|| {
            ApfsError::BadBTree(format!("key index {i} out of range ({} keys)", self.toc.len()))
        })?;
        let key_off = self.keys_area_start() + entry.key_off as usize;
        let key_len = if self.fixed_kv() {
            fixed_key_size as usize
        } else {
            entry.key_len as usize
        };
        let end = key_off + key_len;
        if end > self.block.len() {
            return Err(ApfsError::BadBTree("key slice oob".into()));
        }
        Ok(&self.block[key_off..end])
    }

    /// Slice the i-th value. For internal nodes, the value is always an 8-byte
    /// child OID; pass `0` for both size args and read the result as u64
    pub fn value_at(&self, i: usize, fixed_val_size: u32) -> Result<&[u8]> {
        let entry = self.toc.get(i).ok_or_else(|| {
            ApfsError::BadBTree(format!(
                "value index {i} out of range ({} keys)",
                self.toc.len()
            ))
        })?;
        // Values are stored *backward* from val_area_end: an offset of N means
        // the value starts N bytes BEFORE val_area_end
        let end = self.val_area_end();
        let val_off = end
            .checked_sub(entry.val_off as usize)
            .ok_or_else(|| ApfsError::BadBTree("val_off underflow".into()))?;
        let val_len = if self.fixed_kv() {
            // For internal nodes the values are fixed 8-byte oids regardless
            // of the tree's stated val_size
            if !self.is_leaf() {
                8
            } else {
                fixed_val_size as usize
            }
        } else if !self.is_leaf() {
            8
        } else {
            entry.val_len as usize
        };
        if val_off + val_len > end {
            return Err(ApfsError::BadBTree(format!(
                "val slice oob: off={val_off} len={val_len} end={end}"
            )));
        }
        Ok(&self.block[val_off..val_off + val_len])
    }

    /// Read the i-th child OID. Only valid on internal nodes
    pub fn child_oid_at(&self, i: usize) -> Result<u64> {
        if self.is_leaf() {
            return Err(ApfsError::Internal(
                "child_oid_at called on leaf node".into(),
            ));
        }
        let v = self.value_at(i, 0)?;
        if v.len() < 8 {
            return Err(ApfsError::BadBTree("child oid value too short".into()));
        }
        Ok(u64::from_le_bytes(v[..8].try_into().unwrap()))
    }

    /// Replace the i-th value with bytes of identical length. Used by
    /// catalog inode-mutation paths where the schema preserves value width
    pub fn replace_value(&mut self, i: usize, new_val: &[u8], fixed_val_size: u32) -> Result<()> {
        let len_required = self.value_at(i, fixed_val_size)?.len();
        if new_val.len() != len_required {
            return Err(ApfsError::BadBTree(format!(
                "replace_value: length mismatch (need {len_required}, got {})",
                new_val.len()
            )));
        }
        let entry = self.toc[i];
        let end = self.val_area_end();
        let off = end - entry.val_off as usize;
        self.block[off..off + new_val.len()].copy_from_slice(new_val);
        Ok(())
    }

    /// Insert a `(key, val)` pair into a fixed-KV leaf at position `idx`
    /// Used by OMAP. Bumps `btn_nkeys`, allocates from `btn_free_space`,
    /// rewrites the TOC entry, and updates `btn_table_space` capacity
    pub fn insert_leaf_fixed(
        &mut self,
        idx: usize,
        key: &[u8],
        val: &[u8],
        fixed_key_size: u32,
        fixed_val_size: u32,
    ) -> Result<()> {
        if !self.is_leaf() {
            return Err(ApfsError::BadBTree("insert_leaf_fixed on non-leaf".into()));
        }
        if !self.fixed_kv() {
            return Err(ApfsError::BadBTree(
                "insert_leaf_fixed on variable-KV node".into(),
            ));
        }
        if key.len() != fixed_key_size as usize || val.len() != fixed_val_size as usize {
            return Err(ApfsError::BadBTree("insert_leaf_fixed: size mismatch".into()));
        }
        if idx > self.toc.len() {
            return Err(ApfsError::BadBTree(format!(
                "insert_leaf_fixed: idx {idx} > nkeys {}",
                self.toc.len()
            )));
        }
        // Allocate key/val slots from the free space window inside btn_data
        // free_space.off is relative to the start of btn_data and points at
        // the start of the free key region
        let toc_entry_size = 4u16; // fixed-KV TOC slot
        // We need toc_entry_size + key_len + val_len bytes of free space
        let total_needed = toc_entry_size as u32 + fixed_key_size + fixed_val_size;
        if (self.free_space.len as u32) < total_needed {
            return Err(ApfsError::BadBTree(
                "insert_leaf_fixed: free space exhausted".into(),
            ));
        }

        // Append key bytes at the start of free area (low offsets)
        // `free_space.off` is measured from `keys_area_start` (immediately
        // after btn_table_space), so the absolute write position is
        // `BTNODE_FIXED_PREFIX + keys_area_start + free_space.off`
        let keys_area_off_btn = self.table_space.off + self.table_space.len;
        let new_key_off_btn = keys_area_off_btn + self.free_space.off;
        let abs_key_off = BTNODE_FIXED_PREFIX + new_key_off_btn as usize;
        self.block[abs_key_off..abs_key_off + key.len()].copy_from_slice(key);

        // Append val bytes at the high end of value area. APFS stores val_off
        // as bytes-from-end of the value-area where the value *starts*; with
        // fixed-size values and a parser that reads `val_area_end - val_off`,
        // each new entry sits at (existing_max_val_off + val_len) from the end
        let val_area_end = self.val_area_end();
        let mut max_val_off = 0u16;
        for entry in &self.toc {
            let val_top = entry.val_off + fixed_val_size as u16;
            if val_top > max_val_off {
                max_val_off = val_top;
            }
        }
        let new_val_off_from_end = max_val_off + fixed_val_size as u16;
        let abs_val_off = val_area_end - new_val_off_from_end as usize;
        self.block[abs_val_off..abs_val_off + val.len()].copy_from_slice(val);

        // On-disk key_off is measured from keys_area_start. Our new key
        // landed at offset `self.free_space.off` inside the keys area
        let on_disk_key_off = self.free_space.off;
        let stored_entry = TocEntry {
            key_off: on_disk_key_off,
            key_len: fixed_key_size as u16,
            val_off: new_val_off_from_end,
            val_len: fixed_val_size as u16,
        };
        self.toc.insert(idx, stored_entry);

        // Update bookkeeping
        self.free_space.off += fixed_key_size as u16;
        self.free_space.len -= fixed_key_size as u16 + fixed_val_size as u16;

        // Grow table_space if the TOC has outgrown its current capacity
        let toc_bytes_used = (self.toc.len() as u16) * toc_entry_size;
        if toc_bytes_used > self.table_space.len {
            let extra = toc_bytes_used - self.table_space.len;
            if self.free_space.len < extra {
                return Err(ApfsError::BadBTree(
                    "insert_leaf_fixed: cannot grow toc".into(),
                ));
            }
            self.table_space.len += extra;
            self.free_space.off = self.free_space.off.checked_sub(extra).ok_or_else(|| {
                ApfsError::BadBTree("insert_leaf_fixed: free_space.off underflow on grow".into())
            })?;
            self.free_space.len -= extra;
        }
        Ok(())
    }

    /// Remove the i-th leaf entry. The TOC slot is freed; key/val bytes stay
    /// in place until those offsets are reused. Only called from tests so far
    pub fn delete_leaf(&mut self, i: usize) -> Result<()> {
        if !self.is_leaf() {
            return Err(ApfsError::BadBTree("delete_leaf on non-leaf".into()));
        }
        if i >= self.toc.len() {
            return Err(ApfsError::BadBTree("delete_leaf: idx oob".into()));
        }
        self.toc.remove(i);
        Ok(())
    }

    /// Insert a `(key, val)` pair into a variable-KV leaf at position `idx`
    /// Used by catalog mutation paths (rename / unlink / drec insertion)
    /// Bumps `btn_nkeys`, allocates from `btn_free_space`, rewrites the TOC
    /// entry, and grows `btn_table_space` if the slot table needs more room
    pub fn insert_leaf_var(&mut self, idx: usize, key: &[u8], val: &[u8]) -> Result<()> {
        if !self.is_leaf() {
            return Err(ApfsError::BadBTree("insert_leaf_var on non-leaf".into()));
        }
        if self.fixed_kv() {
            return Err(ApfsError::BadBTree(
                "insert_leaf_var on fixed-KV node".into(),
            ));
        }
        if idx > self.toc.len() {
            return Err(ApfsError::BadBTree(format!(
                "insert_leaf_var: idx {idx} > nkeys {}",
                self.toc.len()
            )));
        }
        let key_len = key.len() as u16;
        let val_len = val.len() as u16;
        if key_len == 0 || val_len == 0 {
            return Err(ApfsError::BadBTree(
                "insert_leaf_var: empty key or value".into(),
            ));
        }
        let toc_entry_size: u16 = 8;
        let total_needed: u32 = toc_entry_size as u32 + key_len as u32 + val_len as u32;
        if (self.free_space.len as u32) < total_needed {
            return Err(ApfsError::BadBTree(
                "insert_leaf_var: free space exhausted".into(),
            ));
        }

        // Place the key bytes at the start of the free area (low offsets)
        // `free_space.off` is measured from `keys_area_start` (immediately
        // after btn_table_space), NOT from btn_data start, so we add
        // `keys_area_start` to land on the right absolute byte
        let keys_area_off_btn = self.table_space.off + self.table_space.len;
        let new_key_off_btn = keys_area_off_btn + self.free_space.off;
        let abs_key_off = BTNODE_FIXED_PREFIX + new_key_off_btn as usize;
        if abs_key_off + key.len() > self.block.len() {
            return Err(ApfsError::BadBTree(
                "insert_leaf_var: key would overflow block".into(),
            ));
        }
        self.block[abs_key_off..abs_key_off + key.len()].copy_from_slice(key);

        // Place the val bytes immediately below the deepest existing value
        // Each entry's `val_off` is the byte offset from `val_area_end` to
        // the LOW address of its value; so the deepest existing slot has
        // the largest `val_off`. The new value's `val_off` is that max
        // plus the new value's length
        let val_area_end = self.val_area_end();
        let max_val_off: u16 = self.toc.iter().map(|e| e.val_off).max().unwrap_or(0);
        let new_val_off_from_end = max_val_off + val_len;
        let abs_val_off = val_area_end
            .checked_sub(new_val_off_from_end as usize)
            .ok_or_else(|| ApfsError::BadBTree("insert_leaf_var: val area underflow".into()))?;
        self.block[abs_val_off..abs_val_off + val.len()].copy_from_slice(val);

        // On-disk key_off is measured from keys_area_start. Our new key
        // landed `self.free_space.off` bytes into the keys area, so the
        // on-disk u16 is exactly that value
        let on_disk_key_off = self.free_space.off;

        let stored_entry = TocEntry {
            key_off: on_disk_key_off,
            key_len,
            val_off: new_val_off_from_end,
            val_len,
        };
        self.toc.insert(idx, stored_entry);

        // Update bookkeeping: keys consume the front of free space; values
        // consume from the back so they don't move free_space.off
        self.free_space.off += key_len;
        self.free_space.len -= key_len + val_len;

        // Grow table_space if the new TOC outgrew the allocated slot region
        let toc_bytes_used = (self.toc.len() as u16) * toc_entry_size;
        if toc_bytes_used > self.table_space.len {
            let extra = toc_bytes_used - self.table_space.len;
            if self.free_space.len < extra {
                return Err(ApfsError::BadBTree(
                    "insert_leaf_var: cannot grow toc".into(),
                ));
            }
            self.table_space.len += extra;
            // `free_space.off` is measured from `keys_area_start`. Growing\
            // the TOC pushes `keys_area_start` forward by `extra` bytes so\
            // the same absolute free position is `extra` bytes closer to it
            self.free_space.off = self.free_space.off.checked_sub(extra).ok_or_else(|| {
                ApfsError::BadBTree("insert_leaf_var: free_space.off underflow on grow".into())
            })?;
            self.free_space.len -= extra;
            // Shift every entry's on-disk key_off down by `extra` since the
            // keys_area_start moved forward; the bytes themselves are still
            // at the same absolute offset within the block
            for entry in &mut self.toc {
                entry.key_off = entry
                    .key_off
                    .checked_sub(extra)
                    .ok_or_else(|| ApfsError::BadBTree(
                        "insert_leaf_var: toc grow overflowed key_off".into(),
                    ))?;
            }
        }
        Ok(())
    }

    /// Remove the i-th entry from a variable-KV leaf. Same TOC bookkeeping
    /// as [`Self::delete_leaf`]; the released key/val byte ranges aren't
    /// compacted (they remain dead inside `btn_data` until the node is
    /// rewritten from scratch). Safe because subsequent inserts only ever
    /// allocate from `free_space` past the live keys
    pub fn delete_leaf_var(&mut self, i: usize) -> Result<()> {
        if !self.is_leaf() {
            return Err(ApfsError::BadBTree("delete_leaf_var on non-leaf".into()));
        }
        if self.fixed_kv() {
            return Err(ApfsError::BadBTree(
                "delete_leaf_var on fixed-KV node".into(),
            ));
        }
        if i >= self.toc.len() {
            return Err(ApfsError::BadBTree("delete_leaf_var: idx oob".into()));
        }
        self.toc.remove(i);
        Ok(())
    }

    /// Write back the node with a fresh checksum and return the block bytes
    pub fn serialize(&mut self) -> Result<&[u8]> {
        // Object header
        self.header.write_into(&mut self.block[..ObjectHeader::SIZE])?;

        // btn fields
        let p = &mut self.block[ObjectHeader::SIZE..ObjectHeader::SIZE + 24];
        p[0..2].copy_from_slice(&self.flags.to_le_bytes());
        p[2..4].copy_from_slice(&self.level.to_le_bytes());
        p[4..8].copy_from_slice(&(self.toc.len() as u32).to_le_bytes());
        self.table_space.write_into(&mut p[8..12]);
        self.free_space.write_into(&mut p[12..16]);
        self.key_free_list.write_into(&mut p[16..20]);
        self.val_free_list.write_into(&mut p[20..24]);

        // TOC
        let toc_off = BTNODE_FIXED_PREFIX + self.table_space.off as usize;
        let is_fixed = self.fixed_kv();
        let toc_entry_size = if is_fixed { 4 } else { 8 };
        for (i, entry) in self.toc.iter().enumerate() {
            let dst = &mut self.block[toc_off + i * toc_entry_size..toc_off + (i + 1) * toc_entry_size];
            if is_fixed {
                dst[0..2].copy_from_slice(&entry.key_off.to_le_bytes());
                dst[2..4].copy_from_slice(&entry.val_off.to_le_bytes());
            } else {
                dst[0..2].copy_from_slice(&entry.key_off.to_le_bytes());
                dst[2..4].copy_from_slice(&entry.key_len.to_le_bytes());
                dst[4..6].copy_from_slice(&entry.val_off.to_le_bytes());
                dst[6..8].copy_from_slice(&entry.val_len.to_le_bytes());
            }
        }

        // Root info footer
        if let Some(info) = self.info {
            let info_off = self.block.len() - BTREE_INFO_SIZE;
            info.write_into(&mut self.block[info_off..]);
        }

        // Refresh checksum
        fletcher::refresh_object_checksum(&mut self.block)?;
        Ok(&self.block)
    }
}

// ---------------------------------------------------------------------------
// Lookup / scan helpers
// ---------------------------------------------------------------------------

/// Resolve a child OID to a paddr. If `omap_root` is `Some`, translate via
/// OMAP; otherwise the OID is itself a paddr (physical tree)
fn resolve_oid<R: Read + Seek>(
    reader: &mut R,
    oid: u64,
    block_size: u32,
    omap_root: Option<u64>,
) -> Result<u64> {
    match omap_root {
        Some(root) => crate::apfs::omap::omap_lookup(reader, root, block_size, oid),
        None => Ok(oid),
    }
}

/// Look up the value matching `compare_fn` in a B-tree rooted at `root_paddr`
pub fn btree_lookup<R: Read + Seek, F>(
    reader: &mut R,
    root_paddr: u64,
    block_size: u32,
    fixed_key_size: u32,
    fixed_val_size: u32,
    compare_fn: &F,
    omap_root: Option<u64>,
) -> Result<Option<Vec<u8>>>
where
    F: Fn(&[u8]) -> Ordering,
{
    Ok(btree_lookup_with_leaf(
        reader,
        root_paddr,
        block_size,
        fixed_key_size,
        fixed_val_size,
        compare_fn,
        omap_root,
    )?
    .map(|(v, _)| v))
}

/// Same as [`btree_lookup`] but also returns the paddr of the leaf that
/// contained the matched entry (for read-modify-write paths)
pub fn btree_lookup_with_leaf<R: Read + Seek, F>(
    reader: &mut R,
    root_paddr: u64,
    block_size: u32,
    fixed_key_size: u32,
    fixed_val_size: u32,
    compare_fn: &F,
    omap_root: Option<u64>,
) -> Result<Option<(Vec<u8>, u64)>>
where
    F: Fn(&[u8]) -> Ordering,
{
    let root_block = read_block(reader, root_paddr, block_size)?;
    let root = BTreeNode::parse(&root_block)?;
    // If the root carries btree_info, it overrides the caller-provided sizes
    let (fks, fvs) = if let Some(info) = root.info {
        (
            if info.key_size != 0 { info.key_size } else { fixed_key_size },
            if info.val_size != 0 { info.val_size } else { fixed_val_size },
        )
    } else {
        (fixed_key_size, fixed_val_size)
    };
    descend_lookup(reader, &root, root_paddr, block_size, fks, fvs, compare_fn, omap_root)
}

fn descend_lookup<R: Read + Seek, F>(
    reader: &mut R,
    node: &BTreeNode,
    node_paddr: u64,
    block_size: u32,
    fks: u32,
    fvs: u32,
    cmp: &F,
    omap_root: Option<u64>,
) -> Result<Option<(Vec<u8>, u64)>>
where
    F: Fn(&[u8]) -> Ordering,
{
    if node.is_leaf() {
        for i in 0..node.nkeys() {
            let key = node.key_at(i, fks)?;
            match cmp(key) {
                Ordering::Equal => {
                    return Ok(Some((node.value_at(i, fvs)?.to_vec(), node_paddr)));
                }
                Ordering::Greater => return Ok(None),
                Ordering::Less => continue,
            }
        }
        return Ok(None);
    }

    // Internal: pick the largest child whose key is <= search key
    let mut chosen: Option<usize> = None;
    for i in 0..node.nkeys() {
        let key = node.key_at(i, fks)?;
        match cmp(key) {
            Ordering::Less | Ordering::Equal => chosen = Some(i),
            Ordering::Greater => break,
        }
    }
    let Some(idx) = chosen else { return Ok(None) };

    let child_oid = node.child_oid_at(idx)?;
    let child_paddr = resolve_oid(reader, child_oid, block_size, omap_root)?;
    let child_block = read_block(reader, child_paddr, block_size)?;
    let child = BTreeNode::parse(&child_block)?;
    descend_lookup(reader, &child, child_paddr, block_size, fks, fvs, cmp, omap_root)
}

/// Scan leaves and collect every `(key, val)` where `range_fn` returns `Some(true)`
/// Return `None` from the closure to stop early
pub fn btree_scan<R: Read + Seek, F>(
    reader: &mut R,
    root_paddr: u64,
    block_size: u32,
    fixed_key_size: u32,
    fixed_val_size: u32,
    range_fn: &F,
    omap_root: Option<u64>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    F: Fn(&[u8]) -> Option<bool>,
{
    let with_leaves = btree_scan_with_leaves(
        reader,
        root_paddr,
        block_size,
        fixed_key_size,
        fixed_val_size,
        range_fn,
        omap_root,
    )?;
    Ok(with_leaves.into_iter().map(|(k, v, _)| (k, v)).collect())
}

/// Like [`btree_scan`] but each tuple also includes the paddr of the leaf
/// that produced the match. Used by mutation paths that need to rewrite
/// every leaf containing a record matching `(oid, type)`
pub fn btree_scan_with_leaves<R: Read + Seek, F>(
    reader: &mut R,
    root_paddr: u64,
    block_size: u32,
    fixed_key_size: u32,
    fixed_val_size: u32,
    range_fn: &F,
    omap_root: Option<u64>,
) -> Result<Vec<(Vec<u8>, Vec<u8>, u64)>>
where
    F: Fn(&[u8]) -> Option<bool>,
{
    let mut out = Vec::new();
    let root_block = read_block(reader, root_paddr, block_size)?;
    let root = BTreeNode::parse(&root_block)?;
    let (fks, fvs) = if let Some(info) = root.info {
        (
            if info.key_size != 0 { info.key_size } else { fixed_key_size },
            if info.val_size != 0 { info.val_size } else { fixed_val_size },
        )
    } else {
        (fixed_key_size, fixed_val_size)
    };
    let _ = scan_node_paddr(
        reader,
        &root,
        root_paddr,
        block_size,
        fks,
        fvs,
        range_fn,
        omap_root,
        &mut out,
    )?;
    Ok(out)
}

fn scan_node_paddr<R: Read + Seek, F>(
    reader: &mut R,
    node: &BTreeNode,
    node_paddr: u64,
    block_size: u32,
    fks: u32,
    fvs: u32,
    range_fn: &F,
    omap_root: Option<u64>,
    out: &mut Vec<(Vec<u8>, Vec<u8>, u64)>,
) -> Result<bool>
where
    F: Fn(&[u8]) -> Option<bool>,
{
    if node.is_leaf() {
        for i in 0..node.nkeys() {
            let key = node.key_at(i, fks)?;
            match range_fn(key) {
                None => return Ok(true),
                Some(true) => {
                    out.push((key.to_vec(), node.value_at(i, fvs)?.to_vec(), node_paddr));
                }
                Some(false) => continue,
            }
        }
        return Ok(false);
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, fks)?;
        if range_fn(key).is_none() {
            return Ok(true);
        }
        let child_oid = node.child_oid_at(i)?;
        let child_paddr = resolve_oid(reader, child_oid, block_size, omap_root)?;
        let child_block = read_block(reader, child_paddr, block_size)?;
        let child = BTreeNode::parse(&child_block)?;
        if scan_node_paddr(
            reader,
            &child,
            child_paddr,
            block_size,
            fks,
            fvs,
            range_fn,
            omap_root,
            out,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fixed-KV leaf node for testing. Each entry is a `(key, val)` u64 pair
    fn build_fixed_leaf(block_size: usize, entries: &[(u64, u64)], is_root: bool) -> Vec<u8> {
        let mut block = vec![0u8; block_size];
        let header = ObjectHeader {
            checksum: [0; 8],
            oid: 1,
            xid: 1,
            raw_type: OBJECT_TYPE_BTREE_NODE as u32,
            subtype: 0,
        };
        header.write_into(&mut block[..32]).unwrap();

        let mut node_flags = flags::LEAF | flags::FIXED_KV_SIZE;
        if is_root {
            node_flags |= flags::ROOT;
        }
        let p = &mut block[ObjectHeader::SIZE..ObjectHeader::SIZE + 24];
        p[0..2].copy_from_slice(&node_flags.to_le_bytes());
        p[2..4].copy_from_slice(&0u16.to_le_bytes()); // level
        p[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());

        // table_space placed at start of btn_data
        let toc_entry_size: u16 = 4;
        let toc_capacity: u16 = (entries.len() as u16) * toc_entry_size + 8; // a little slack
        let table_space = Nloc {
            off: 0,
            len: toc_capacity,
        };
        table_space.write_into(&mut p[8..12]);

        // Lay out keys forward, values backward
        let key_size = 8u16;
        let val_size = 8u16;
        let keys_area_start = BTNODE_FIXED_PREFIX + toc_capacity as usize;
        let val_area_end = if is_root {
            block_size - BTREE_INFO_SIZE
        } else {
            block_size
        };

        // Place keys + record TOC entries
        let mut on_disk_key_off: u16 = 0;
        let mut val_top: u16 = 0; // bytes-from-end-of-val-area to start-of-newest-val-block
        let mut toc_entries = Vec::new();
        for (k, v) in entries {
            let abs_key_off = keys_area_start + on_disk_key_off as usize;
            block[abs_key_off..abs_key_off + 8].copy_from_slice(&k.to_le_bytes());
            val_top += val_size;
            let abs_val_off = val_area_end - val_top as usize;
            block[abs_val_off..abs_val_off + 8].copy_from_slice(&v.to_le_bytes());

            toc_entries.push((on_disk_key_off, val_top));
            on_disk_key_off += key_size;
        }

        // Free space spans whatever is between the end-of-keys and the
        // start-of-values inside btn_data
        let free_off = toc_capacity + on_disk_key_off;
        let free_len = (val_area_end - BTNODE_FIXED_PREFIX) as u16 - free_off - val_top;
        Nloc {
            off: free_off,
            len: free_len,
        }
        .write_into(&mut block[ObjectHeader::SIZE + 12..ObjectHeader::SIZE + 16]);
        // key_free_list / val_free_list = 0
        Nloc { off: 0, len: 0 }.write_into(&mut block[ObjectHeader::SIZE + 16..ObjectHeader::SIZE + 20]);
        Nloc { off: 0, len: 0 }.write_into(&mut block[ObjectHeader::SIZE + 20..ObjectHeader::SIZE + 24]);

        // Write TOC entries
        let toc_off = BTNODE_FIXED_PREFIX;
        for (i, (k_off, v_off)) in toc_entries.iter().enumerate() {
            let dst = &mut block[toc_off + i * 4..toc_off + (i + 1) * 4];
            dst[0..2].copy_from_slice(&k_off.to_le_bytes());
            dst[2..4].copy_from_slice(&v_off.to_le_bytes());
        }

        // Root footer
        if is_root {
            let info = BTreeInfo {
                flags: 0,
                node_size: block_size as u32,
                key_size: 8,
                val_size: 8,
                longest_key: 8,
                longest_val: 8,
                key_count: entries.len() as u64,
                node_count: 1,
            };
            info.write_into(&mut block[block_size - BTREE_INFO_SIZE..]);
        }

        fletcher::refresh_object_checksum(&mut block).unwrap();
        block
    }

    #[test]
    fn parse_then_lookup_in_synthetic_root_leaf() {
        let block = build_fixed_leaf(4096, &[(1, 100), (5, 500), (9, 900)], true);
        let node = BTreeNode::parse(&block).unwrap();
        assert_eq!(node.nkeys(), 3);
        assert!(node.is_leaf());
        assert!(node.is_root());
        for (i, (k, v)) in [(1u64, 100u64), (5, 500), (9, 900)].iter().enumerate() {
            let key_bytes = node.key_at(i, 8).unwrap();
            let val_bytes = node.value_at(i, 8).unwrap();
            assert_eq!(u64::from_le_bytes(key_bytes.try_into().unwrap()), *k);
            assert_eq!(u64::from_le_bytes(val_bytes.try_into().unwrap()), *v);
        }
    }

    #[test]
    fn replace_value_in_place() {
        let block = build_fixed_leaf(4096, &[(7, 70)], true);
        let mut node = BTreeNode::parse(&block).unwrap();
        node.replace_value(0, &999u64.to_le_bytes(), 8).unwrap();
        let bytes = node.serialize().unwrap().to_vec();
        let reparsed = BTreeNode::parse(&bytes).unwrap();
        let v = u64::from_le_bytes(reparsed.value_at(0, 8).unwrap().try_into().unwrap());
        assert_eq!(v, 999);
    }

    #[test]
    fn serialize_refreshes_checksum() {
        let block = build_fixed_leaf(4096, &[(2, 22)], true);
        let mut node = BTreeNode::parse(&block).unwrap();
        // Mutate something via replace_value to invalidate the checksum, then serialize
        node.replace_value(0, &44u64.to_le_bytes(), 8).unwrap();
        let bytes = node.serialize().unwrap().to_vec();
        assert!(fletcher::verify_object(&bytes));
    }

    #[test]
    fn lookup_returns_none_for_missing_key() {
        use std::io::Cursor as IoCursor;
        let block = build_fixed_leaf(4096, &[(10, 100), (20, 200)], true);
        // Embed in a 1-block "disk" so the lookup helper can read paddr 0
        let disk = block;
        let mut reader = IoCursor::new(disk);
        let cmp = |k: &[u8]| u64::from_le_bytes(k.try_into().unwrap()).cmp(&15u64);
        let res = btree_lookup(&mut reader, 0, 4096, 8, 8, &cmp, None).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn lookup_finds_existing_key() {
        use std::io::Cursor as IoCursor;
        let block = build_fixed_leaf(4096, &[(10, 100), (20, 200)], true);
        let mut reader = IoCursor::new(block);
        let cmp = |k: &[u8]| u64::from_le_bytes(k.try_into().unwrap()).cmp(&20u64);
        let val = btree_lookup(&mut reader, 0, 4096, 8, 8, &cmp, None)
            .unwrap()
            .unwrap();
        assert_eq!(u64::from_le_bytes(val.try_into().unwrap()), 200);
    }

    #[test]
    fn scan_returns_all_matches() {
        use std::io::Cursor as IoCursor;
        let block = build_fixed_leaf(4096, &[(1, 1), (3, 3), (5, 5), (7, 7)], true);
        let mut reader = IoCursor::new(block);
        let predicate = |k: &[u8]| {
            let v = u64::from_le_bytes(k.try_into().unwrap());
            if v > 5 {
                None
            } else {
                Some(v % 2 == 1)
            }
        };
        let matches = btree_scan(&mut reader, 0, 4096, 8, 8, &predicate, None).unwrap();
        assert_eq!(matches.len(), 3);
    }
}
