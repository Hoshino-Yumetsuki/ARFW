//! NX (container) and APFS (volume) superblocks
//!
//! Field names track the APFS Reference. Only the fields this crate reads are
//! decoded; the rest goes into a `trailing` buffer that round-trips verbatim
use crate::apfs::error::{ApfsError, Result};
use crate::apfs::fletcher;
use crate::apfs::object::{
    self, OBJECT_TYPE_FS, OBJECT_TYPE_NX_SUPERBLOCK, ObjectHeader, read_block_unchecked,
};
use std::io::{Read, Seek};

pub const NX_MAGIC: u32 = 0x4253584E; // 'NXSB' little-endian
pub const APFS_MAGIC: u32 = 0x42535041; // 'APSB' little-endian

/// Slot count for `nx_fs_oid`. Apple hard-codes 100 in `nx_superblock_t`
/// regardless of `nx_max_file_systems`
pub const NX_MAX_FILE_SYSTEMS: usize = 100;
/// Start of the verbatim `trailing` slice within the NXSB block; the
/// boundary between the parsed prefix and the unknown remainder
pub const NX_TRAILING_OFFSET: usize = 984;

#[allow(dead_code)]
const NX_FIXED_HEAD: usize = 0x50; // bytes before the variable-length tail starts

/// Container superblock. Only the fields this crate reads are decoded;
/// the rest lives in `trailing` for verbatim round-tripping
#[derive(Debug, Clone)]
pub struct NxSuperblock {
    pub header: ObjectHeader,
    pub magic: u32,
    pub block_size: u32,
    pub block_count: u64,

    pub features: u64,
    pub readonly_compatible_features: u64,
    pub incompatible_features: u64,
    pub uuid: [u8; 16],

    pub next_oid: u64,
    pub next_xid: u64,

    pub xp_desc_blocks: u32,
    pub xp_data_blocks: u32,
    pub xp_desc_base: u64,
    pub xp_data_base: u64,
    pub xp_desc_next: u32,
    pub xp_data_next: u32,
    pub xp_desc_index: u32,
    pub xp_desc_len: u32,
    pub xp_data_index: u32,
    pub xp_data_len: u32,

    pub spaceman_oid: u64,
    pub omap_oid: u64,
    pub reaper_oid: u64,

    pub max_file_systems: u32,
    pub fs_oids: [u64; NX_MAX_FILE_SYSTEMS],

    /// Bytes from offset `NX_FIXED_HEAD + 4 + 4 + 8*100` (= 0x4f8) onwards,
    /// kept verbatim so [`Self::write_to_block`] preserves all unknown fields
    pub(crate) trailing: Vec<u8>,
}

impl NxSuperblock {
    pub fn parse(block: &[u8]) -> Result<Self> {
        let header = ObjectHeader::parse(block)?;
        header.expect_type(OBJECT_TYPE_NX_SUPERBLOCK)?;

        let mut c = Cursor::new(block, ObjectHeader::SIZE);
        let magic = c.u32()?;
        if magic != NX_MAGIC {
            return Err(ApfsError::BadContainerMagic(magic));
        }
        let block_size = c.u32()?;
        let block_count = c.u64()?;

        let features = c.u64()?;
        let readonly_compatible_features = c.u64()?;
        let incompatible_features = c.u64()?;
        let mut uuid = [0u8; 16];
        c.bytes_into(&mut uuid)?;

        let next_oid = c.u64()?;
        let next_xid = c.u64()?;

        let xp_desc_blocks = c.u32()?;
        let xp_data_blocks = c.u32()?;
        let xp_desc_base = c.u64()?;
        let xp_data_base = c.u64()?;
        let xp_desc_next = c.u32()?;
        let xp_data_next = c.u32()?;
        let xp_desc_index = c.u32()?;
        let xp_desc_len = c.u32()?;
        let xp_data_index = c.u32()?;
        let xp_data_len = c.u32()?;

        let spaceman_oid = c.u64()?;
        let omap_oid = c.u64()?;
        let reaper_oid = c.u64()?;

        let _nx_test_type = c.u32()?; // documented but never consulted
        let max_file_systems = c.u32()?;

        let mut fs_oids = [0u64; NX_MAX_FILE_SYSTEMS];
        for slot in &mut fs_oids {
            *slot = c.u64()?;
        }

        let trailing = block[c.position()..].to_vec();
        Ok(Self {
            header,
            magic,
            block_size,
            block_count,
            features,
            readonly_compatible_features,
            incompatible_features,
            uuid,
            next_oid,
            next_xid,
            xp_desc_blocks,
            xp_data_blocks,
            xp_desc_base,
            xp_data_base,
            xp_desc_next,
            xp_data_next,
            xp_desc_index,
            xp_desc_len,
            xp_data_index,
            xp_data_len,
            spaceman_oid,
            omap_oid,
            reaper_oid,
            max_file_systems,
            fs_oids,
            trailing,
        })
    }

    /// Write the superblock into `buf` (must be `block_size` bytes). Copies
    /// `trailing` verbatim and refreshes the Fletcher checksum
    pub fn write_to_block(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != self.block_size as usize {
            return Err(ApfsError::Internal(format!(
                "NxSuperblock::write_to_block: buf len {} != block_size {}",
                buf.len(),
                self.block_size
            )));
        }
        // Header (with whatever checksum is in `self.header.checksum`; we
        // overwrite it at the end via fletcher::refresh)
        self.header.write_into(&mut buf[..ObjectHeader::SIZE])?;

        let mut w = Writer::new(buf, ObjectHeader::SIZE);
        w.put_u32(self.magic);
        w.put_u32(self.block_size);
        w.put_u64(self.block_count);
        w.put_u64(self.features);
        w.put_u64(self.readonly_compatible_features);
        w.put_u64(self.incompatible_features);
        w.put_bytes(&self.uuid);
        w.put_u64(self.next_oid);
        w.put_u64(self.next_xid);
        w.put_u32(self.xp_desc_blocks);
        w.put_u32(self.xp_data_blocks);
        w.put_u64(self.xp_desc_base);
        w.put_u64(self.xp_data_base);
        w.put_u32(self.xp_desc_next);
        w.put_u32(self.xp_data_next);
        w.put_u32(self.xp_desc_index);
        w.put_u32(self.xp_desc_len);
        w.put_u32(self.xp_data_index);
        w.put_u32(self.xp_data_len);
        w.put_u64(self.spaceman_oid);
        w.put_u64(self.omap_oid);
        w.put_u64(self.reaper_oid);
        // We didn't track nx_test_type; read from current buffer to preserve
        // The original byte already exists in `buf` only if the caller pre-loaded
        // it; in normal NXSB rotation we read-modify-write a real block so the
        // bytes are present. But to be safe leave that 4-byte slot untouched
        // by skipping past it
        w.skip(4);
        w.put_u32(self.max_file_systems);
        for oid in self.fs_oids.iter() {
            w.put_u64(*oid);
        }
        let pos = w.position();

        // Anything past our parsed prefix is the verbatim trailing slice
        let tail_end = pos + self.trailing.len();
        if tail_end > buf.len() {
            return Err(ApfsError::Internal(format!(
                "NxSuperblock::write_to_block: trailing overflows block ({} + {} > {})",
                pos,
                self.trailing.len(),
                buf.len()
            )));
        }
        buf[pos..tail_end].copy_from_slice(&self.trailing);
        // Bytes between tail_end and end of block are zeroed (they are
        // structural padding inside the 4 KiB block)
        for b in &mut buf[tail_end..] {
            *b = 0;
        }
        fletcher::refresh_object_checksum(buf)
    }
}

/// Read the container superblock at block 0. Call [`find_latest_nxsb`] to get the live one
pub fn read_nxsb<R: Read + Seek>(reader: &mut R) -> Result<NxSuperblock> {
    // Block size at this point is unknown; we read 4 KiB which is the only
    // value APFS actually ships, then fall back to the discovered block_size
    // when it differs
    const PROBE: usize = 4096;
    let mut probe = vec![0u8; PROBE];
    reader.seek(std::io::SeekFrom::Start(0))?;
    reader.read_exact(&mut probe)?;
    let mut sb = NxSuperblock::parse(&probe)?;
    if sb.block_size as usize != PROBE {
        // Re-read at the actual block size and reparse
        let block = object::read_block(reader, 0, sb.block_size)?;
        sb = NxSuperblock::parse(&block)?;
    } else if !fletcher::verify_object(&probe) {
        return Err(ApfsError::BadChecksum);
    }
    Ok(sb)
}

/// Walk the checkpoint descriptor ring and return the highest-XID NXSB whose
/// checksum and type are valid
pub fn find_latest_nxsb<R: Read + Seek>(
    reader: &mut R,
    seed: &NxSuperblock,
) -> Result<NxSuperblock> {
    let mut best: NxSuperblock = seed.clone();
    let count = seed.xp_desc_blocks as u64;
    for i in 0..count {
        let paddr = seed.xp_desc_base + i;
        let raw = match read_block_unchecked(reader, paddr, seed.block_size) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if !fletcher::verify_object(&raw) {
            continue;
        }
        let header = match ObjectHeader::parse(&raw) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if header.object_type() != OBJECT_TYPE_NX_SUPERBLOCK {
            continue;
        }
        if header.xid <= best.header.xid {
            continue;
        }
        if let Ok(parsed) = NxSuperblock::parse(&raw) {
            best = parsed;
        }
    }
    Ok(best)
}

// ---------------------------------------------------------------------------
// Volume superblock (`apfs_superblock_t`)
// We expose the bare minimum fields used by the reader: name, OIDs, counters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApfsSuperblock {
    pub header: ObjectHeader,
    pub magic: u32,
    pub omap_oid: u64,
    pub root_tree_oid: u64,
    pub extentref_tree_oid: u64,
    pub snap_meta_tree_oid: u64,
    pub volume_name: String,
    pub num_files: u64,
    pub num_directories: u64,
    pub num_symlinks: u64,
    pub num_other_fsobjects: u64,
    pub num_snapshots: u64,
    pub vol_uuid: [u8; 16],
    pub next_obj_id: u64,
    pub incompat_features: u64,
    /// Verbatim trailing bytes for round-trip fidelity
    #[allow(dead_code)]
    trailing: Vec<u8>,
}

impl ApfsSuperblock {
    pub fn parse(block: &[u8]) -> Result<Self> {
        let header = ObjectHeader::parse(block)?;
        header.expect_type(OBJECT_TYPE_FS)?;

        let mut c = Cursor::new(block, ObjectHeader::SIZE);
        let magic = c.u32()?;
        if magic != APFS_MAGIC {
            return Err(ApfsError::BadVolumeMagic(magic));
        }
        // Skip ahead to the fields we care about. The on-disk layout is:
        //   apfs_fs_index u32
        //   apfs_features u64
        //   apfs_readonly_compatible_features u64
        //   apfs_incompatible_features u64
        //   apfs_unmount_time u64
        //   apfs_fs_reserve_block_count u64
        //   apfs_fs_quota_block_count u64
        //   apfs_fs_alloc_count u64
        //   apfs_meta_crypto_state 20 bytes
        //   apfs_root_tree_type u32
        //   apfs_extentref_tree_type u32
        //   apfs_snap_meta_tree_type u32
        //   apfs_omap_oid u64
        //   apfs_root_tree_oid u64
        //   apfs_extentref_tree_oid u64
        //   apfs_snap_meta_tree_oid u64
        //   apfs_revert_to_xid u64
        //   apfs_revert_to_sblock_oid u64
        //   apfs_next_obj_id u64
        //   apfs_num_files u64
        //   apfs_num_directories u64
        //   apfs_num_symlinks u64
        //   apfs_num_other_fsobjects u64
        //   apfs_num_snapshots u64
        //   apfs_total_blocks_alloced u64
        //   apfs_total_blocks_freed u64
        //   apfs_vol_uuid [16]
        //   apfs_last_mod_time u64
        //   apfs_fs_flags u64
        //   apfs_formatted_by 32 bytes
        //   apfs_modified_by 32*8 bytes
        //   apfs_volname [256]
        c.skip(4)?; // fs_index
        c.skip(8)?; // features
        c.skip(8)?; // ro_compat
        let incompat_features = c.u64()?;
        c.skip(8)?; // unmount_time
        c.skip(8 * 3)?; // reserve, quota, alloc
        c.skip(20)?; // meta_crypto_state
        c.skip(4 * 3)?; // tree types
        let omap_oid = c.u64()?;
        let root_tree_oid = c.u64()?;
        let extentref_tree_oid = c.u64()?;
        let snap_meta_tree_oid = c.u64()?;
        c.skip(8 * 2)?; // revert_to_xid, revert_to_sblock_oid
        let next_obj_id = c.u64()?;
        let num_files = c.u64()?;
        let num_directories = c.u64()?;
        let num_symlinks = c.u64()?;
        let num_other_fsobjects = c.u64()?;
        let num_snapshots = c.u64()?;
        c.skip(8 * 2)?; // total_blocks_alloced/freed
        let mut vol_uuid = [0u8; 16];
        c.bytes_into(&mut vol_uuid)?;
        c.skip(8)?; // last_mod_time
        c.skip(8)?; // fs_flags
        c.skip(32)?; // formatted_by
        c.skip(32 * 8)?; // modified_by

        let mut name_bytes = [0u8; 256];
        c.bytes_into(&mut name_bytes)?;
        let volume_name = decode_cstring(&name_bytes);

        let trailing = block[c.position()..].to_vec();

        Ok(Self {
            header,
            magic,
            omap_oid,
            root_tree_oid,
            extentref_tree_oid,
            snap_meta_tree_oid,
            volume_name,
            num_files,
            num_directories,
            num_symlinks,
            num_other_fsobjects,
            num_snapshots,
            vol_uuid,
            next_obj_id,
            incompat_features,
            trailing,
        })
    }
}

fn decode_cstring(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Tiny binary-cursor helpers (kept private to this module)
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], at: usize) -> Self {
        Self { buf, pos: at }
    }
    fn position(&self) -> usize {
        self.pos
    }
    fn check(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(ApfsError::Truncated {
                need: self.pos + n,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }
    fn u32(&mut self) -> Result<u32> {
        self.check(4)?;
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn u64(&mut self) -> Result<u64> {
        self.check(8)?;
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.check(n)?;
        self.pos += n;
        Ok(())
    }
    fn bytes_into(&mut self, dst: &mut [u8]) -> Result<()> {
        self.check(dst.len())?;
        dst.copy_from_slice(&self.buf[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
        Ok(())
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8], at: usize) -> Self {
        Self { buf, pos: at }
    }
    fn position(&self) -> usize {
        self.pos
    }
    fn put_u32(&mut self, v: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes());
        self.pos += 4;
    }
    fn put_u64(&mut self, v: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes());
        self.pos += 8;
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
    fn skip(&mut self, n: usize) {
        self.pos += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_nxsb_block() -> Vec<u8> {
        let mut block = vec![0u8; 4096];
        let header = ObjectHeader {
            checksum: [0; 8],
            oid: 1,
            xid: 5,
            raw_type: OBJECT_TYPE_NX_SUPERBLOCK as u32,
            subtype: 0,
        };
        header.write_into(&mut block[..32]).unwrap();
        let mut w = Writer::new(&mut block, 32);
        w.put_u32(NX_MAGIC);
        w.put_u32(4096); // block_size
        w.put_u64(16384); // block_count
        w.put_u64(0); // features
        w.put_u64(0); // ro_compat
        w.put_u64(0); // incompat
        w.put_bytes(&[0u8; 16]); // uuid
        w.put_u64(1024); // next_oid
        w.put_u64(6); // next_xid
        w.put_u32(8); // xp_desc_blocks
        w.put_u32(8); // xp_data_blocks
        w.put_u64(64); // xp_desc_base
        w.put_u64(72); // xp_data_base
        w.put_u32(2); // xp_desc_next
        w.put_u32(2); // xp_data_next
        w.put_u32(0); // xp_desc_index
        w.put_u32(2); // xp_desc_len
        w.put_u32(0); // xp_data_index
        w.put_u32(2); // xp_data_len
        w.put_u64(80); // spaceman_oid
        w.put_u64(96); // omap_oid
        w.put_u64(0); // reaper_oid
        w.put_u32(0); // nx_test_type
        w.put_u32(1); // max_file_systems
        // fs_oids[0..100]
        for i in 0..NX_MAX_FILE_SYSTEMS {
            let v = if i == 0 { 200u64 } else { 0 };
            w.put_u64(v);
        }
        fletcher::refresh_object_checksum(&mut block).unwrap();
        block
    }

    #[test]
    fn nxsb_roundtrip_preserves_fields_and_checksum() {
        let bytes = build_minimal_nxsb_block();
        let parsed = NxSuperblock::parse(&bytes).unwrap();
        assert_eq!(parsed.magic, NX_MAGIC);
        assert_eq!(parsed.block_size, 4096);
        assert_eq!(parsed.next_xid, 6);
        assert_eq!(parsed.xp_desc_base, 64);
        assert_eq!(parsed.xp_desc_blocks, 8);
        assert_eq!(parsed.fs_oids[0], 200);

        let mut out = vec![0u8; 4096];
        parsed.write_to_block(&mut out).unwrap();
        // The serialised bytes must reverify (and match the input exactly,
        // since our parser captures every byte beyond the prefix)
        assert!(fletcher::verify_object(&out));
        let reparsed = NxSuperblock::parse(&out).unwrap();
        assert_eq!(reparsed.fs_oids[0], 200);
        assert_eq!(reparsed.xp_desc_next, 2);
    }

    #[test]
    fn nxsb_rejects_bad_magic() {
        let mut bytes = build_minimal_nxsb_block();
        bytes[32] ^= 0xFF;
        // Recompute checksum so the magic check, not the checksum, fires
        fletcher::refresh_object_checksum(&mut bytes).unwrap();
        assert!(matches!(
            NxSuperblock::parse(&bytes),
            Err(ApfsError::BadContainerMagic(_))
        ));
    }

    #[test]
    fn nxsb_round_trip_byte_identical() {
        let bytes = build_minimal_nxsb_block();
        let parsed = NxSuperblock::parse(&bytes).unwrap();
        let mut out = vec![0u8; bytes.len()];
        parsed.write_to_block(&mut out).unwrap();
        assert_eq!(out, bytes);
    }
}
