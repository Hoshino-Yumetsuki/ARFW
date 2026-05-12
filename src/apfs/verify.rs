//! Structural validator for an APFS image
use std::collections::HashSet;
use std::io::{Read, Seek};

use crate::apfs::btree::BTreeNode;
use crate::apfs::error::{ApfsError, Result};
use crate::apfs::fletcher;
use crate::apfs::object::{self, ObjectHeader};
use crate::apfs::omap;
use crate::apfs::superblock::{self, ApfsSuperblock, NxSuperblock};

#[derive(Debug, Default, Clone)]
pub struct VerifyReport {
    pub blocks_checked: u64,
    pub btree_nodes_visited: u64,
    pub volumes: u32,
    pub max_xid: u64,
    pub checkpoint_nxsb_count: u32,
}

/// Walk an APFS image end-to-end, verifying every checksum
pub fn verify_image<R: Read + Seek>(reader: &mut R) -> Result<VerifyReport> {
    let mut report = VerifyReport::default();

    let nxsb0 = superblock::read_nxsb(reader)?;
    report.blocks_checked += 1;
    if nxsb0.magic != superblock::NX_MAGIC {
        return Err(ApfsError::BadContainerMagic(nxsb0.magic));
    }

    let nxsb = scan_checkpoint_ring(reader, &nxsb0, &mut report)?;
    report.max_xid = report.max_xid.max(nxsb.header.xid);
    if nxsb.header.xid < nxsb0.header.xid {
        return Err(ApfsError::BadCatalog(format!(
            "checkpoint NXSB xid {} regressed below block-0 xid {}",
            nxsb.header.xid, nxsb0.header.xid
        )));
    }

    let block_size = nxsb.block_size;

    let container_omap_root = omap::read_omap_tree_root(reader, nxsb.omap_oid, block_size)?;
    verify_block(reader, nxsb.omap_oid, block_size, &mut report)?;
    walk_btree(reader, container_omap_root, block_size, None, &mut report)?;

    for &vol_oid in nxsb.fs_oids.iter() {
        if vol_oid == 0 {
            continue;
        }
        let apsb_block = omap::omap_lookup(reader, container_omap_root, block_size, vol_oid)?;
        let apsb_data = object::read_block(reader, apsb_block, block_size)?;
        if !fletcher::verify_object(&apsb_data) {
            return Err(ApfsError::BadChecksum);
        }
        let apsb = ApfsSuperblock::parse(&apsb_data)?;
        report.blocks_checked += 1;
        report.volumes += 1;
        report.max_xid = report.max_xid.max(apsb.header.xid);

        if apsb.magic != superblock::APFS_MAGIC {
            return Err(ApfsError::BadVolumeMagic(apsb.magic));
        }
        if apsb.header.xid > nxsb.header.xid {
            return Err(ApfsError::BadCatalog(format!(
                "APSB xid {} exceeds NXSB xid {}",
                apsb.header.xid, nxsb.header.xid
            )));
        }

        let vol_omap_root = omap::read_omap_tree_root(reader, apsb.omap_oid, block_size)?;
        verify_block(reader, apsb.omap_oid, block_size, &mut report)?;
        walk_btree(reader, vol_omap_root, block_size, None, &mut report)?;

        let catalog_root =
            omap::omap_lookup(reader, vol_omap_root, block_size, apsb.root_tree_oid)?;
        walk_btree(
            reader,
            catalog_root,
            block_size,
            Some(vol_omap_root),
            &mut report,
        )?;

        if apsb.extentref_tree_oid != 0 {
            walk_btree(
                reader,
                apsb.extentref_tree_oid,
                block_size,
                None,
                &mut report,
            )?;
        }
    }

    Ok(report)
}

fn scan_checkpoint_ring<R: Read + Seek>(
    reader: &mut R,
    nxsb: &NxSuperblock,
    report: &mut VerifyReport,
) -> Result<NxSuperblock> {
    let block_size = nxsb.block_size;
    let mut best: Option<NxSuperblock> = None;
    for i in 0..nxsb.xp_desc_blocks as u64 {
        let block_num = nxsb.xp_desc_base + i;
        let block = match object::read_block(reader, block_num, block_size) {
            Ok(b) => b,
            Err(_) => continue,
        };
        report.blocks_checked += 1;
        if !fletcher::verify_object(&block) {
            if let Ok(header) = ObjectHeader::parse(&block) {
                if header.object_type() == object::OBJECT_TYPE_NX_SUPERBLOCK {
                    return Err(ApfsError::BadChecksum);
                }
            }
            continue;
        }
        let header = match ObjectHeader::parse(&block) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if header.object_type() != object::OBJECT_TYPE_NX_SUPERBLOCK {
            continue;
        }
        let candidate = match NxSuperblock::parse(&block) {
            Ok(sb) => sb,
            Err(_) => continue,
        };
        if candidate.magic != superblock::NX_MAGIC {
            continue;
        }
        report.checkpoint_nxsb_count += 1;
        match &best {
            Some(b) if b.header.xid >= candidate.header.xid => {}
            _ => best = Some(candidate),
        }
    }
    Ok(best.unwrap_or_else(|| nxsb.clone()))
}

fn verify_block<R: Read + Seek>(
    reader: &mut R,
    block_num: u64,
    block_size: u32,
    report: &mut VerifyReport,
) -> Result<()> {
    let data = object::read_block(reader, block_num, block_size)?;
    report.blocks_checked += 1;
    if !fletcher::verify_object(&data) {
        return Err(ApfsError::BadChecksum);
    }
    Ok(())
}

fn walk_btree<R: Read + Seek>(
    reader: &mut R,
    root_block: u64,
    block_size: u32,
    omap_root: Option<u64>,
    report: &mut VerifyReport,
) -> Result<()> {
    let mut visited: HashSet<u64> = HashSet::new();
    walk_btree_node(
        reader,
        root_block,
        block_size,
        omap_root,
        report,
        &mut visited,
    )
}

fn walk_btree_node<R: Read + Seek>(
    reader: &mut R,
    block_num: u64,
    block_size: u32,
    omap_root: Option<u64>,
    report: &mut VerifyReport,
    visited: &mut HashSet<u64>,
) -> Result<()> {
    if !visited.insert(block_num) {
        return Ok(());
    }
    let data = object::read_block(reader, block_num, block_size)?;
    report.blocks_checked += 1;
    report.btree_nodes_visited += 1;
    if !fletcher::verify_object(&data) {
        return Err(ApfsError::BadChecksum);
    }
    let node = BTreeNode::parse(&data)?;
    if node.is_leaf() {
        return Ok(());
    }
    for i in 0..node.nkeys() {
        let child_oid = node.child_oid_at(i)?;
        let child_block = match omap_root {
            None => child_oid,
            Some(or) => omap::omap_lookup(reader, or, block_size, child_oid)?,
        };
        walk_btree_node(reader, child_block, block_size, omap_root, report, visited)?;
    }
    Ok(())
}
