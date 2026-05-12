//! Physical extent reference tree (`extentref`): record format helpers
use crate::apfs::error::{ApfsError, Result};

pub const J_OBJ_KIND_NEW: u8 = 0;
pub const PEXT_KIND_SHIFT: u32 = 60;
pub const PEXT_LEN_MASK: u64 = (1u64 << 60) - 1;

/// Wire size of a `PhysExtKey` record on disk
pub const PHYS_EXT_KEY_SIZE: u32 = 8;
/// Wire size of a `PhysExtVal` record on disk
pub const PHYS_EXT_VAL_SIZE: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysExtKey {
    pub paddr: u64,
}

impl PhysExtKey {
    pub const SIZE: usize = 8;

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(ApfsError::BadBTree("phys_ext key too short".into()));
        }
        let raw = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        Ok(Self {
            paddr: raw & PEXT_LEN_MASK,
        })
    }

    pub fn to_bytes(self, kind: u64) -> [u8; 8] {
        let raw = (self.paddr & PEXT_LEN_MASK) | (kind << PEXT_KIND_SHIFT);
        raw.to_le_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysExtVal {
    pub length: u64,
    pub kind: u8,
    pub owning_obj_id: u64,
    pub refcnt: i32,
}

impl PhysExtVal {
    pub const SIZE: usize = 20;

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(ApfsError::BadBTree("phys_ext val too short".into()));
        }
        let len_and_kind = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let owning_obj_id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let refcnt = i32::from_le_bytes(buf[16..20].try_into().unwrap());
        Ok(Self {
            length: len_and_kind & PEXT_LEN_MASK,
            kind: (len_and_kind >> PEXT_KIND_SHIFT) as u8,
            owning_obj_id,
            refcnt,
        })
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        let len_and_kind =
            (self.length & PEXT_LEN_MASK) | ((self.kind as u64) << PEXT_KIND_SHIFT);
        out[0..8].copy_from_slice(&len_and_kind.to_le_bytes());
        out[8..16].copy_from_slice(&self.owning_obj_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.refcnt.to_le_bytes());
        out
    }

    pub fn inc(&mut self) -> Result<i32> {
        self.refcnt = self
            .refcnt
            .checked_add(1)
            .ok_or_else(|| ApfsError::Internal("phys_ext refcnt overflow".into()))?;
        Ok(self.refcnt)
    }

    pub fn dec(&mut self) -> Result<i32> {
        if self.refcnt <= 0 {
            return Err(ApfsError::Internal("phys_ext refcnt underflow".into()));
        }
        self.refcnt -= 1;
        Ok(self.refcnt)
    }
}

// ---------------------------------------------------------------------------
// B-tree mutation helpers
//
// The extentref tree is a *physical* (no-OMAP) fixed-KV B-tree keyed by the
// extent's starting paddr. Records are sparse; only allocated extents are
// present. These helpers operate on the leaf that contains (or would contain)
// a given paddr; the caller is responsible for descending the tree to find
// the right leaf and for staging the modified leaf bytes through a
// `Transaction`
// ---------------------------------------------------------------------------

use crate::apfs::btree::{BTreeNode, btree_lookup_with_leaf};
use crate::apfs::object::read_block;
use std::cmp::Ordering;
use std::io::{Read, Seek};

/// Look up the extentref record for `paddr` and return the value plus the
/// paddr of the leaf node containing it
pub fn extentref_lookup<R: Read + Seek>(
    reader: &mut R,
    extentref_root: u64,
    block_size: u32,
    paddr: u64,
) -> Result<Option<(PhysExtVal, u64)>> {
    let cmp = move |k: &[u8]| -> Ordering {
        match PhysExtKey::parse(k) {
            Ok(key) => key.paddr.cmp(&paddr),
            Err(_) => Ordering::Less,
        }
    };
    let hit = btree_lookup_with_leaf(
        reader,
        extentref_root,
        block_size,
        PHYS_EXT_KEY_SIZE,
        PHYS_EXT_VAL_SIZE,
        &cmp,
        None,
    )?;
    match hit {
        Some((bytes, leaf_paddr)) => {
            let val = PhysExtVal::parse(&bytes)?;
            Ok(Some((val, leaf_paddr)))
        }
        None => Ok(None),
    }
}

/// In-place increment of an existing record's refcount inside `node`. Returns
/// the new refcount. The caller must serialise the node and stage the block
pub fn extentref_inc_in_node(node: &mut BTreeNode, paddr: u64) -> Result<i32> {
    let idx = find_record_idx(node, paddr)?
        .ok_or_else(|| ApfsError::NotFound(format!("extentref paddr {paddr}")))?;
    let bytes = node.value_at(idx, PHYS_EXT_VAL_SIZE)?;
    let mut val = PhysExtVal::parse(bytes)?;
    let new = val.inc()?;
    node.replace_value(idx, &val.to_bytes(), PHYS_EXT_VAL_SIZE)?;
    Ok(new)
}

/// In-place decrement of an existing record's refcount inside `node`. Returns
/// `(new_refcount, removed)`. When `removed` is `true` the record was deleted
/// because the count fell to zero; caller is responsible for freeing the
/// underlying blocks via the space manager
pub fn extentref_dec_in_node(node: &mut BTreeNode, paddr: u64) -> Result<(i32, bool)> {
    let idx = find_record_idx(node, paddr)?
        .ok_or_else(|| ApfsError::NotFound(format!("extentref paddr {paddr}")))?;
    let bytes = node.value_at(idx, PHYS_EXT_VAL_SIZE)?;
    let mut val = PhysExtVal::parse(bytes)?;
    let new = val.dec()?;
    if new == 0 {
        node.delete_leaf(idx)?;
        Ok((0, true))
    } else {
        node.replace_value(idx, &val.to_bytes(), PHYS_EXT_VAL_SIZE)?;
        Ok((new, false))
    }
}

/// Insert a fresh extentref record into the leaf `node` at the correct
/// sorted position. `kind` is normally `J_OBJ_KIND_NEW`. Returns the
/// insertion index
pub fn extentref_insert_in_node(
    node: &mut BTreeNode,
    paddr: u64,
    val: PhysExtVal,
    kind: u64,
) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "extentref_insert_in_node: not a leaf".into(),
        ));
    }
    // Sorted insert by paddr
    let mut idx = node.toc.len();
    for i in 0..node.nkeys() {
        let existing = PhysExtKey::parse(node.key_at(i, PHYS_EXT_KEY_SIZE)?)?;
        match existing.paddr.cmp(&paddr) {
            Ordering::Less => continue,
            Ordering::Equal => {
                return Err(ApfsError::Internal(format!(
                    "extentref_insert_in_node: duplicate paddr {paddr}"
                )));
            }
            Ordering::Greater => {
                idx = i;
                break;
            }
        }
    }
    let key = PhysExtKey { paddr };
    node.insert_leaf_fixed(
        idx,
        &key.to_bytes(kind),
        &val.to_bytes(),
        PHYS_EXT_KEY_SIZE,
        PHYS_EXT_VAL_SIZE,
    )?;
    Ok(idx)
}

/// Locate the TOC index of the record matching `paddr` within the leaf
fn find_record_idx(node: &BTreeNode, paddr: u64) -> Result<Option<usize>> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree("extentref helper called on non-leaf".into()));
    }
    for i in 0..node.nkeys() {
        let key = PhysExtKey::parse(node.key_at(i, PHYS_EXT_KEY_SIZE)?)?;
        if key.paddr == paddr {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Convenience: read the leaf at `leaf_paddr`, mutate via `f`, and return
/// the new (serialised) block bytes. The caller stages the result through a
/// `Transaction`
pub fn extentref_modify_leaf<R, F, T>(
    reader: &mut R,
    leaf_paddr: u64,
    block_size: u32,
    f: F,
) -> Result<(Vec<u8>, T)>
where
    R: Read + Seek,
    F: FnOnce(&mut BTreeNode) -> Result<T>,
{
    let block = read_block(reader, leaf_paddr, block_size)?;
    let mut node = BTreeNode::parse(&block)?;
    let out = f(&mut node)?;
    let bytes = node.serialize()?.to_vec();
    Ok((bytes, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn val_roundtrip() {
        let v = PhysExtVal {
            length: 16,
            kind: 0,
            owning_obj_id: 100,
            refcnt: 3,
        };
        let parsed = PhysExtVal::parse(&v.to_bytes()).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn inc_dec() {
        let mut v = PhysExtVal {
            length: 1,
            kind: 0,
            owning_obj_id: 1,
            refcnt: 1,
        };
        assert_eq!(v.inc().unwrap(), 2);
        assert_eq!(v.dec().unwrap(), 1);
        assert_eq!(v.dec().unwrap(), 0);
        assert!(v.dec().is_err());
    }

    #[test]
    fn key_kind_strip() {
        let k = PhysExtKey { paddr: 0x12345 };
        let parsed = PhysExtKey::parse(&k.to_bytes(8)).unwrap();
        assert_eq!(parsed.paddr, 0x12345);
    }

    #[test]
    fn val_packs_length_and_kind() {
        let v = PhysExtVal {
            length: 0x0FFF_FFFF_FFFF_FFFF,
            kind: 0x0F,
            owning_obj_id: 1,
            refcnt: 0,
        };
        let parsed = PhysExtVal::parse(&v.to_bytes()).unwrap();
        assert_eq!(parsed.length, 0x0FFF_FFFF_FFFF_FFFF);
        assert_eq!(parsed.kind, 0x0F);
    }
}
