//! Transaction commit pipeline
//!
//! Two commit modes: `commit_in_place` (no rotation, opt-in) and
//! `commit_with_nxsb_rotation` (publishes a fresh NXSB into the descriptor
//! ring so a crash mid-commit cannot leave the container in an inconsistent
//! state)
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::apfs::error::{ApfsError, Result};
use crate::apfs::fletcher::refresh_object_checksum;
use crate::apfs::object::ObjectHeader;
use crate::apfs::superblock::NxSuperblock;

pub struct Transaction {
    block_size: u64,
    dirty: BTreeMap<u64, Vec<u8>>,
    /// Opt-in latch for `commit_in_place`; that path skips NXSB rotation
    /// and is unsafe when a concurrent reader may observe the volume
    pub allow_in_place_commit: bool,
}

impl Transaction {
    pub fn new(block_size: u64) -> Self {
        Self {
            block_size,
            dirty: BTreeMap::new(),
            allow_in_place_commit: false,
        }
    }

    pub fn stage(&mut self, paddr: u64, block: Vec<u8>) -> Result<()> {
        if block.len() as u64 != self.block_size {
            return Err(ApfsError::Internal(format!(
                "tx stage: block len {} != block_size {}",
                block.len(),
                self.block_size
            )));
        }
        self.dirty.insert(paddr, block);
        Ok(())
    }

    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    pub fn iter_dirty(&self) -> impl Iterator<Item = (&u64, &Vec<u8>)> {
        self.dirty.iter()
    }

    /// Commit all staged blocks to their original paddrs (no NXSB rotation)
    pub fn commit_in_place<RW: Read + Write + Seek>(self, rw: &mut RW) -> Result<usize> {
        if !self.allow_in_place_commit {
            return Err(ApfsError::Internal(
                "Transaction::commit_in_place: not enabled".into(),
            ));
        }
        Self::write_all_dirty(&self.dirty, self.block_size, rw)?;
        rw.flush()?;
        Ok(self.dirty.len())
    }

    /// Commit staged blocks AND publish a fresh NXSB into the next slot of
    /// the descriptor ring
    pub fn commit_with_nxsb_rotation<RW: Read + Write + Seek>(
        self,
        rw: &mut RW,
        nxsb: &NxSuperblock,
    ) -> Result<(usize, u64)> {
        if self.block_size != nxsb.block_size as u64 {
            return Err(ApfsError::Internal(format!(
                "block_size mismatch: tx={} nxsb={}",
                self.block_size, nxsb.block_size
            )));
        }
        if nxsb.xp_desc_blocks == 0 {
            return Err(ApfsError::Internal(
                "xp_desc_blocks is zero; cannot rotate NXSB".into(),
            ));
        }

        let block_size = self.block_size;
        let new_xid = nxsb.next_xid.max(nxsb.header.xid + 1);

        let desc_lo = nxsb.xp_desc_base;
        let desc_hi = nxsb.xp_desc_base + nxsb.xp_desc_blocks as u64;
        let data_lo = nxsb.xp_data_base;
        let data_hi = nxsb.xp_data_base + nxsb.xp_data_blocks as u64;
        let in_ring = |p: u64| (p >= desc_lo && p < desc_hi) || (p >= data_lo && p < data_hi);

        let mut dirty = self.dirty;
        for (paddr, block) in dirty.iter_mut() {
            if in_ring(*paddr) {
                continue;
            }
            if let Ok(mut hdr) = ObjectHeader::parse(block) {
                hdr.xid = new_xid;
                hdr.write_into(&mut block[..ObjectHeader::SIZE])?;
            }
        }

        Self::write_all_dirty(&dirty, block_size, rw)?;
        rw.flush()?;

        let new_desc_next = (nxsb.xp_desc_next + 1) % nxsb.xp_desc_blocks;
        let new_desc_len = (nxsb.xp_desc_len + 1).min(nxsb.xp_desc_blocks);
        let new_nxsb_paddr = nxsb.xp_desc_base + nxsb.xp_desc_next as u64;

        let mut new_nxsb = nxsb.clone();
        new_nxsb.header.xid = new_xid;
        new_nxsb.next_xid = new_xid + 1;
        new_nxsb.xp_desc_next = new_desc_next;
        new_nxsb.xp_desc_len = new_desc_len;

        let target_offset = new_nxsb_paddr * block_size;
        let mut nxsb_buf = vec![0u8; block_size as usize];
        rw.seek(SeekFrom::Start(target_offset))?;
        let _ = rw.read_exact(&mut nxsb_buf);

        new_nxsb.write_to_block(&mut nxsb_buf)?;

        rw.seek(SeekFrom::Start(target_offset))?;
        rw.write_all(&nxsb_buf)?;
        rw.flush()?;

        Ok((dirty.len(), new_nxsb_paddr))
    }

    fn write_all_dirty<RW: Write + Seek>(
        dirty: &BTreeMap<u64, Vec<u8>>,
        block_size: u64,
        rw: &mut RW,
    ) -> Result<()> {
        for (paddr, block) in dirty.iter() {
            let offset = paddr
                .checked_mul(block_size)
                .ok_or_else(|| ApfsError::Internal(format!("paddr {paddr} overflows offset")))?;
            let mut tmp = block.clone();
            refresh_object_checksum(&mut tmp)?;
            rw.seek(SeekFrom::Start(offset))?;
            rw.write_all(&tmp)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs::fletcher;
    use crate::apfs::object::OBJECT_TYPE_BTREE_NODE;
    use std::io::Cursor;

    fn make_nxsb(xid: u64, desc_next: u32, desc_len: u32) -> NxSuperblock {
        // Build a minimal valid NXSB by serializing a synthesised one through
        // a 4 KiB block; relies on the round-tripping behaviour of the
        // superblock module
        let mut nx = NxSuperblock {
            header: ObjectHeader {
                checksum: [0; 8],
                oid: 1,
                xid,
                raw_type: crate::apfs::object::OBJECT_TYPE_NX_SUPERBLOCK as u32,
                subtype: 0,
            },
            magic: crate::apfs::superblock::NX_MAGIC,
            block_size: 4096,
            block_count: 64,
            features: 0,
            readonly_compatible_features: 0,
            incompatible_features: 0,
            uuid: [0u8; 16],
            next_oid: 0x4000,
            next_xid: xid + 1,
            xp_desc_blocks: 4,
            xp_data_blocks: 2,
            xp_desc_base: 8,
            xp_data_base: 16,
            xp_desc_next: desc_next,
            xp_data_next: 0,
            xp_desc_index: 0,
            xp_desc_len: desc_len,
            xp_data_index: 0,
            xp_data_len: 0,
            spaceman_oid: 0,
            omap_oid: 0,
            reaper_oid: 0,
            max_file_systems: 0,
            fs_oids: [0u64; crate::apfs::superblock::NX_MAX_FILE_SYSTEMS],
            trailing: vec![0u8; 4096 - crate::apfs::superblock::NX_TRAILING_OFFSET],
        };
        let _ = &mut nx;
        nx
    }

    #[test]
    fn rejects_wrong_block_size() {
        let mut tx = Transaction::new(4096);
        let err = tx.stage(10, vec![0u8; 4095]).unwrap_err();
        assert!(format!("{err}").contains("block len"));
    }

    #[test]
    fn refuses_in_place_without_optin() {
        let mut tx = Transaction::new(4096);
        tx.stage(10, vec![0u8; 4096]).unwrap();
        let mut backing = Cursor::new(vec![0u8; 4096 * 16]);
        let err = tx.commit_in_place(&mut backing).unwrap_err();
        assert!(format!("{err}").contains("not enabled"));
    }

    #[test]
    fn in_place_commit_refreshes_checksum() {
        let mut backing = Cursor::new(vec![0u8; 4096 * 4]);
        let mut block = vec![0xABu8; 4096];
        // Place a parseable header so refresh has a valid object to checksum
        let hdr = ObjectHeader {
            checksum: [0; 8],
            oid: 1,
            xid: 1,
            raw_type: OBJECT_TYPE_BTREE_NODE as u32,
            subtype: 0,
        };
        hdr.write_into(&mut block[..ObjectHeader::SIZE]).unwrap();

        let mut tx = Transaction::new(4096);
        tx.stage(2, block).unwrap();
        tx.allow_in_place_commit = true;
        assert_eq!(tx.commit_in_place(&mut backing).unwrap(), 1);

        let written = &backing.get_ref()[8192..8192 + 4096];
        assert!(fletcher::verify_object(written));
    }

    #[test]
    fn nxsb_rotation_publishes_next_slot() {
        const BS: u32 = 4096;
        let mut backing = Cursor::new(vec![0u8; (BS as usize) * 64]);

        let nxsb = make_nxsb(5, 0, 0);
        let mut buf = vec![0u8; BS as usize];
        nxsb.write_to_block(&mut buf).unwrap();
        backing.get_mut()[..BS as usize].copy_from_slice(&buf);

        let meta_hdr = ObjectHeader {
            checksum: [0; 8],
            oid: 0x4001,
            xid: 5,
            raw_type: OBJECT_TYPE_BTREE_NODE as u32,
            subtype: 0,
        };
        let mut meta_block = vec![0u8; BS as usize];
        meta_hdr.write_into(&mut meta_block).unwrap();

        let mut tx = Transaction::new(BS as u64);
        tx.stage(20, meta_block).unwrap();
        let (n, new_paddr) = tx.commit_with_nxsb_rotation(&mut backing, &nxsb).unwrap();
        assert_eq!(n, 1);
        assert_eq!(new_paddr, 8);

        let m20 = &backing.get_ref()[20 * BS as usize..21 * BS as usize];
        assert!(fletcher::verify_object(m20));
        let parsed = ObjectHeader::parse(m20).unwrap();
        assert_eq!(parsed.xid, 6);

        let new_nxsb_bytes = &backing.get_ref()[8 * BS as usize..9 * BS as usize];
        assert!(fletcher::verify_object(new_nxsb_bytes));
        let new_nxsb = NxSuperblock::parse(new_nxsb_bytes).unwrap();
        assert_eq!(new_nxsb.header.xid, 6);
        assert_eq!(new_nxsb.xp_desc_next, 1);
        assert_eq!(new_nxsb.xp_desc_len, 1);
    }

    #[test]
    fn nxsb_rotation_wraps_at_ring_end() {
        const BS: u32 = 4096;
        let mut backing = Cursor::new(vec![0u8; (BS as usize) * 32]);
        let nxsb = make_nxsb(10, 3, 4);
        let mut buf = vec![0u8; BS as usize];
        nxsb.write_to_block(&mut buf).unwrap();
        backing.get_mut()[..BS as usize].copy_from_slice(&buf);

        let tx = Transaction::new(BS as u64);
        let (_, new_paddr) = tx.commit_with_nxsb_rotation(&mut backing, &nxsb).unwrap();
        assert_eq!(new_paddr, 8 + 3);
        let written = &backing.get_ref()[(8 + 3) * BS as usize..(8 + 4) * BS as usize];
        let new_nxsb = NxSuperblock::parse(written).unwrap();
        assert_eq!(new_nxsb.xp_desc_next, 0);
        assert_eq!(new_nxsb.xp_desc_len, 4);
    }
}
