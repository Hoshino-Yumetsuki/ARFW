//! Checkpoint descriptor / data ring helpers
//!
//! At commit time APFS rotates through two on-disk ring buffers anchored at
//! `nx_xp_desc_base` and `nx_xp_data_base`. Each transaction writes a fresh
//! NXSB plus a `checkpoint_map_phys_t` that maps every ephemeral OID to its
//! freshly-placed paddr. For read-side resolution we walk the descriptor
//! ring of the latest NXSB looking for the most recent checkpoint map that
//! covers the requested OID
use std::io::{Read, Seek};

use crate::apfs::error::{ApfsError, Result};
use crate::apfs::fletcher;
use crate::apfs::object::{self, OBJECT_TYPE_CHECKPOINT_MAP, ObjectHeader};
use crate::apfs::superblock::NxSuperblock;

#[derive(Debug, Clone)]
pub struct CheckpointMapping {
    pub object_type: u32,
    pub subtype: u32,
    pub size: u32,
    pub _pad: u32,
    pub fs_oid: u64,
    pub oid: u64,
    pub paddr: u64,
}

impl CheckpointMapping {
    pub const SIZE: usize = 40;
}

#[derive(Debug, Clone)]
pub struct CheckpointMap {
    pub flags: u32,
    pub count: u32,
    pub mappings: Vec<CheckpointMapping>,
    pub xid: u64,
}

impl CheckpointMap {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < ObjectHeader::SIZE + 8 {
            return Err(ApfsError::BadCatalog("checkpoint map too short".into()));
        }
        let header = ObjectHeader::parse(raw)?;
        let body = &raw[ObjectHeader::SIZE..];
        let flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let mut mappings = Vec::with_capacity(count as usize);
        let mut off = 8usize;
        for _ in 0..count {
            if body.len() < off + CheckpointMapping::SIZE {
                return Err(ApfsError::BadCatalog(
                    "checkpoint map mappings truncated".into(),
                ));
            }
            let m = &body[off..off + CheckpointMapping::SIZE];
            mappings.push(CheckpointMapping {
                object_type: u32::from_le_bytes(m[0..4].try_into().unwrap()),
                subtype: u32::from_le_bytes(m[4..8].try_into().unwrap()),
                size: u32::from_le_bytes(m[8..12].try_into().unwrap()),
                _pad: u32::from_le_bytes(m[12..16].try_into().unwrap()),
                fs_oid: u64::from_le_bytes(m[16..24].try_into().unwrap()),
                oid: u64::from_le_bytes(m[24..32].try_into().unwrap()),
                paddr: u64::from_le_bytes(m[32..40].try_into().unwrap()),
            });
            off += CheckpointMapping::SIZE;
        }
        Ok(Self {
            flags,
            count,
            mappings,
            xid: header.xid,
        })
    }

    pub fn lookup(&self, oid: u64) -> Option<u64> {
        self.mappings.iter().find(|m| m.oid == oid).map(|m| m.paddr)
    }
}

/// Locate the latest paddr for an ephemeral OID by scanning checkpoint maps
pub fn resolve_ephemeral<R: Read + Seek>(
    reader: &mut R,
    nxsb: &NxSuperblock,
    oid: u64,
) -> Result<u64> {
    let block_size = nxsb.block_size;
    let mut best: Option<(u64, u64)> = None;

    for i in 0..nxsb.xp_desc_blocks as u64 {
        let block_no = nxsb.xp_desc_base + i;
        let raw = match object::read_block(reader, block_no, block_size) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if !fletcher::verify_object(&raw) {
            continue;
        }
        let Ok(hdr) = ObjectHeader::parse(&raw) else {
            continue;
        };
        if hdr.object_type() != OBJECT_TYPE_CHECKPOINT_MAP {
            continue;
        }
        let Ok(map) = CheckpointMap::parse(&raw) else {
            continue;
        };
        if map.xid > nxsb.header.xid {
            continue;
        }
        if let Some(paddr) = map.lookup(oid) {
            match best {
                Some((bx, _)) if bx >= map.xid => {}
                _ => best = Some((map.xid, paddr)),
            }
        }
    }

    best.map(|(_, p)| p)
        .ok_or_else(|| ApfsError::NotFound(format!("ephemeral oid {oid:#x}")))
}
