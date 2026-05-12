//! Object map (OMAP)
//!
//! An OMAP is a `(oid, xid) -> paddr` translation B-tree. Container objects
//! use the container's OMAP to resolve virtual OIDs (volume superblocks,
//! reaper) and each volume has its own OMAP for catalog/extentref/snap-meta
//! tree roots
//!
//! Parses `omap_phys_t` to get the tree OID, translates it to a paddr via
//! the physical OMAP root, and exposes `omap_lookup(oid) -> paddr`
use crate::apfs::btree::{btree_lookup_with_leaf, btree_scan};
use crate::apfs::error::{ApfsError, Result};
use crate::apfs::object::{self, OBJECT_TYPE_OMAP, ObjectHeader, read_block};
use std::cmp::Ordering;
use std::io::{Read, Seek};

/// Layout of `omap_key_t` on disk
pub const OMAP_KEY_SIZE: u32 = 16;
/// Layout of `omap_val_t` on disk
pub const OMAP_VAL_SIZE: u32 = 16;

#[derive(Debug, Clone, Copy)]
pub struct OmapKey {
    pub oid: u64,
    pub xid: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct OmapVal {
    pub flags: u32,
    pub size: u32,
    pub paddr: u64,
}

impl OmapKey {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < OMAP_KEY_SIZE as usize {
            return Err(ApfsError::Truncated {
                need: OMAP_KEY_SIZE as usize,
                have: b.len(),
            });
        }
        Ok(Self {
            oid: u64::from_le_bytes(b[..8].try_into().unwrap()),
            xid: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        })
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.oid.to_le_bytes());
        out[8..16].copy_from_slice(&self.xid.to_le_bytes());
        out
    }
}

impl OmapVal {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < OMAP_VAL_SIZE as usize {
            return Err(ApfsError::Truncated {
                need: OMAP_VAL_SIZE as usize,
                have: b.len(),
            });
        }
        Ok(Self {
            flags: u32::from_le_bytes(b[..4].try_into().unwrap()),
            size: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            paddr: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        })
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&self.flags.to_le_bytes());
        out[4..8].copy_from_slice(&self.size.to_le_bytes());
        out[8..16].copy_from_slice(&self.paddr.to_le_bytes());
        out
    }
}

/// Read the `omap_phys_t` at `omap_oid` (a physical block number) and return
/// the paddr of the B-tree root
pub fn read_omap_tree_root<R: Read + Seek>(
    reader: &mut R,
    omap_oid: u64,
    block_size: u32,
) -> Result<u64> {
    let block = object::read_block(reader, omap_oid, block_size)?;
    let header = ObjectHeader::parse(&block)?;
    header.expect_type(OBJECT_TYPE_OMAP)?;
    // omap_phys layout (offset from start of object body, after 32-byte header):
    //   om_flags u32
    //   om_snap_count u32
    //   om_tree_type u32
    //   om_snapshot_tree_type u32
    //   om_tree_oid u64    <-- the field we want (it's a *physical* OID)
    //   om_snapshot_tree_oid u64
    //   om_most_recent_snap u64
    //   om_pending_revert_min u64
    //   om_pending_revert_max u64
    let body = &block[ObjectHeader::SIZE..];
    if body.len() < 16 + 8 {
        return Err(ApfsError::Truncated {
            need: 24,
            have: body.len(),
        });
    }
    let tree_oid = u64::from_le_bytes(body[16..24].try_into().unwrap());
    Ok(tree_oid)
}

/// Resolve an OID to its latest paddr. APFS keys entries by `(oid, xid)`;
/// we pick the one with the highest xid
pub fn omap_lookup<R: Read + Seek>(
    reader: &mut R,
    omap_root: u64,
    block_size: u32,
    oid: u64,
) -> Result<u64> {
    let cmp = move |key: &[u8]| -> Ordering {
        match OmapKey::parse(key) {
            Ok(k) => k.oid.cmp(&oid),
            Err(_) => Ordering::Less,
        }
    };
    let hit = btree_lookup_with_leaf(
        reader,
        omap_root,
        block_size,
        OMAP_KEY_SIZE,
        OMAP_VAL_SIZE,
        &cmp,
        None,
    )?;
    let (val, _leaf_paddr) = hit.ok_or_else(|| ApfsError::NotFound(format!("omap oid {oid}")))?;
    Ok(OmapVal::parse(&val)?.paddr)
}

/// Scan the OMAP for all mappings with the given oid. Used by the verifier to spot-check translations
pub fn omap_scan<R: Read + Seek>(
    reader: &mut R,
    omap_root: u64,
    block_size: u32,
    target_oid: u64,
) -> Result<Vec<(OmapKey, OmapVal)>> {
    let range = move |key: &[u8]| -> Option<bool> {
        match OmapKey::parse(key) {
            Ok(k) => match k.oid.cmp(&target_oid) {
                Ordering::Less => Some(false),
                Ordering::Equal => Some(true),
                Ordering::Greater => None,
            },
            Err(_) => Some(false),
        }
    };
    let entries = btree_scan(
        reader,
        omap_root,
        block_size,
        OMAP_KEY_SIZE,
        OMAP_VAL_SIZE,
        &range,
        None,
    )?;
    let mut out = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        out.push((OmapKey::parse(&k)?, OmapVal::parse(&v)?));
    }
    Ok(out)
}

/// Insert an `(oid, xid) -> paddr` entry into the leaf at `leaf_paddr`. Caller
/// must pick a leaf with enough free space and commit the block after
///
/// Returns the insertion index
pub fn omap_insert_at_leaf<R: Read + Seek>(
    reader: &mut R,
    leaf_paddr: u64,
    block_size: u32,
    oid: u64,
    xid: u64,
    paddr: u64,
) -> Result<usize> {
    let block = read_block(reader, leaf_paddr, block_size)?;
    let mut node = crate::apfs::btree::BTreeNode::parse(&block)?;
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "omap_insert_at_leaf: target node is not a leaf".into(),
        ));
    }
    let key = OmapKey { oid, xid };
    let val = OmapVal {
        flags: 0,
        size: block_size,
        paddr,
    };
    // Insert in (oid, xid) order
    let mut idx = 0;
    for i in 0..node.nkeys() {
        let existing = OmapKey::parse(node.key_at(i, OMAP_KEY_SIZE)?)?;
        match (existing.oid, existing.xid).cmp(&(oid, xid)) {
            Ordering::Less => idx = i + 1,
            Ordering::Equal => {
                return Err(ApfsError::Internal(
                    "omap_insert_at_leaf: duplicate (oid, xid)".into(),
                ));
            }
            Ordering::Greater => break,
        }
    }
    node.insert_leaf_fixed(idx, &key.to_bytes(), &val.to_bytes(), OMAP_KEY_SIZE, OMAP_VAL_SIZE)?;
    // Caller is expected to grab the serialised block via `node.serialize()`
    let _ = node;
    Ok(idx)
}
