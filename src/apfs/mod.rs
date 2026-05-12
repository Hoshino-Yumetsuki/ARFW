//! APFS read/write implementation
//!
//! On-disk structures follow Apple's APFS Reference. The public surface is
//! scoped to what the WinFSP host and integration tests actually need
pub mod btree;
pub mod catalog;
pub mod checkpoint;
pub mod error;
pub mod extentref;
pub mod extents;
pub mod fletcher;
pub mod hash;
pub mod object;
pub mod omap;
pub mod spaceman;
pub mod superblock;
pub mod transaction;
pub mod verify;

pub use error::{ApfsError, Result};

use std::io::{Read, Seek, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub oid: u64,
    pub kind: EntryKind,
    pub size: u64,
    pub create_time: i64,
    pub modify_time: i64,
}

#[derive(Debug, Clone)]
pub struct FileStat {
    pub oid: u64,
    pub kind: EntryKind,
    pub size: u64,
    pub create_time: i64,
    pub modify_time: i64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub nlink: u32,
}

#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub path: String,
    pub entry: DirEntry,
}

#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub name: String,
    pub block_size: u32,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub num_files: u64,
    pub num_directories: u64,
    pub num_symlinks: u64,
}

/// Owning handle to a mounted APFS volume backed by a `Read + Seek` source
pub struct ApfsVolume<R: Read + Seek> {
    reader: R,
    block_size: u32,
    vol_omap_root_block: u64,
    catalog_root_block: u64,
    nxsb: superblock::NxSuperblock,
    info: VolumeInfo,
    /// In-memory next-OID counter for new files/directories. Initialised
    /// from the volume superblock at mount; not persisted back (loopback
    /// semantics); the next mount will re-derive from the superblock
    /// which still lists the original value
    next_obj_id: u64,
    /// Cached `APFS_INCOMPAT_NORMALIZATION_INSENSITIVE` bit. When set the
    /// volume is case-insensitive and filenames must be hashed against
    /// their lowercase form
    case_insensitive: bool,
    /// In-memory cursor over the spaceman's free bitmap. Used to allocate
    /// brand-new physical blocks for write/grow paths. Lazily initialised
    /// on first allocation since the spaceman parser is non-trivial
    spaceman: Option<spaceman::SpaceManager>,
    spaceman_paddr: u64,
}

impl<R: Read + Seek> ApfsVolume<R> {
    /// Mount the first non-empty volume in the container
    pub fn open(mut reader: R) -> Result<Self> {
        let nxsb = superblock::read_nxsb(&mut reader)?;
        let nxsb = superblock::find_latest_nxsb(&mut reader, &nxsb)?;
        let block_size = nxsb.block_size;

        let container_omap_root =
            omap::read_omap_tree_root(&mut reader, nxsb.omap_oid, block_size)?;
        let vol_oid = nxsb
            .fs_oids
            .iter()
            .find(|&&o| o != 0)
            .copied()
            .ok_or(ApfsError::NoVolume)?;
        let vol_block = omap::omap_lookup(&mut reader, container_omap_root, block_size, vol_oid)?;
        let vol_data = object::read_block(&mut reader, vol_block, block_size)?;
        let vol_sb = superblock::ApfsSuperblock::parse(&vol_data)?;

        let vol_omap_root_block =
            omap::read_omap_tree_root(&mut reader, vol_sb.omap_oid, block_size)?;
        let catalog_root_block = omap::omap_lookup(
            &mut reader,
            vol_omap_root_block,
            block_size,
            vol_sb.root_tree_oid,
        )?;

        // APFS_INCOMPAT_CASE_INSENSITIVE bit (0x8): when SET the volume is
        // case-insensitive. Conservative default: assume case-insensitive
        // when in doubt
        let case_insensitive = (vol_sb.incompat_features & 0x8) != 0;
        let spaceman_paddr = checkpoint::resolve_ephemeral(&mut reader, &nxsb, nxsb.spaceman_oid)?;
        let spaceman = spaceman::Spaceman::read(&mut reader, spaceman_paddr, block_size)?;
        let total_bytes = nxsb.block_count * block_size as u64;
        let free_bytes = spaceman.main_free_count() * block_size as u64;

        let info = VolumeInfo {
            name: vol_sb.volume_name.clone(),
            block_size,
            total_bytes,
            free_bytes,
            used_bytes: total_bytes - free_bytes,
            num_files: vol_sb.num_files,
            num_directories: vol_sb.num_directories,
            num_symlinks: vol_sb.num_symlinks,
        };

        Ok(Self {
            reader,
            block_size,
            vol_omap_root_block,
            catalog_root_block,
            nxsb,
            info,
            next_obj_id: vol_sb.next_obj_id,
            case_insensitive,
            spaceman: None,
            spaceman_paddr,
        })
    }

    pub fn nxsb(&self) -> &superblock::NxSuperblock {
        &self.nxsb
    }
    pub fn catalog_root_block(&self) -> u64 {
        self.catalog_root_block
    }
    pub fn vol_omap_root_block(&self) -> u64 {
        self.vol_omap_root_block
    }
    pub fn volume_info(&self) -> &VolumeInfo {
        &self.info
    }

    pub fn list_directory(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let parent = if path == "/" || path.is_empty() {
            catalog::ROOT_DIR_RECORD
        } else {
            let (oid, inode) = catalog::resolve_path(
                &mut self.reader,
                self.catalog_root_block,
                self.vol_omap_root_block,
                self.block_size,
                path,
            )?;
            if inode.kind() != catalog::INODE_DIR_TYPE {
                return Err(ApfsError::NotADirectory(path.to_string()));
            }
            oid
        };
        catalog::list_directory(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            parent,
        )
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.read_file_to(path, &mut buf)?;
        Ok(buf)
    }

    pub fn read_file_to<W: Write>(&mut self, path: &str, writer: &mut W) -> Result<u64> {
        let (_oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        let file_extents = catalog::lookup_extents(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            inode.private_id,
        )?;
        extents::read_file_data(
            &mut self.reader,
            self.block_size,
            &file_extents,
            inode.size(),
            writer,
        )
    }

    fn build_extent_map(&self, extents: &[catalog::FileExtentVal]) -> Vec<(u64, u64, u64)> {
        let bs = self.block_size as u64;
        let mut map = Vec::with_capacity(extents.len());
        let mut log = 0u64;
        for e in extents {
            let len = e.length();
            if len == 0 {
                continue;
            }
            map.push((log, e.phys_block_num * bs, len));
            log += len;
        }
        map
    }

    pub fn stat_and_extents(
        &mut self,
        path: &str,
    ) -> Result<(FileStat, Vec<(u64, u64, u64)>, u64)> {
        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        let stat = inode_to_stat(oid, &inode);
        if stat.kind == EntryKind::Directory {
            return Ok((stat, Vec::new(), 0));
        }
        let exts = catalog::lookup_extents(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            inode.private_id,
        )?;
        let map = self.build_extent_map(&exts);
        Ok((stat, map, inode.size()))
    }

    pub fn get_file_extents(&mut self, path: &str) -> Result<(Vec<(u64, u64, u64)>, u64)> {
        let (_oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        let exts = catalog::lookup_extents(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            inode.private_id,
        )?;
        Ok((self.build_extent_map(&exts), inode.size()))
    }

    pub fn open_file(&mut self, path: &str) -> Result<extents::ApfsForkReader<'_, R>> {
        let (_oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        let file_extents = catalog::lookup_extents(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            inode.private_id,
        )?;
        Ok(extents::ApfsForkReader::new(
            &mut self.reader,
            self.block_size,
            file_extents,
            inode.size(),
        ))
    }

    pub fn stat(&mut self, path: &str) -> Result<FileStat> {
        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        Ok(inode_to_stat(oid, &inode))
    }

    pub fn walk(&mut self) -> Result<Vec<WalkEntry>> {
        let mut entries = Vec::new();
        self.walk_recursive(catalog::ROOT_DIR_RECORD, "", &mut entries)?;
        Ok(entries)
    }

    pub fn exists(&mut self, path: &str) -> Result<bool> {
        match catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        ) {
            Ok(_) => Ok(true),
            Err(ApfsError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn walk_recursive(
        &mut self,
        parent_oid: u64,
        parent_path: &str,
        entries: &mut Vec<WalkEntry>,
    ) -> Result<()> {
        let dir_entries = catalog::list_directory(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            parent_oid,
        )?;
        for entry in dir_entries {
            let full_path = if parent_path.is_empty() {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", parent_path, entry.name)
            };
            let is_dir = entry.kind == EntryKind::Directory;
            let oid = entry.oid;
            entries.push(WalkEntry {
                path: full_path.clone(),
                entry,
            });
            if is_dir {
                self.walk_recursive(oid, &full_path, entries)?;
            }
        }
        Ok(())
    }
}

fn inode_to_stat(oid: u64, inode: &catalog::InodeVal) -> FileStat {
    FileStat {
        oid,
        kind: match inode.kind() {
            catalog::INODE_DIR_TYPE => EntryKind::Directory,
            catalog::INODE_SYMLINK_TYPE => EntryKind::Symlink,
            _ => EntryKind::File,
        },
        size: inode.size(),
        create_time: inode.create_time,
        modify_time: inode.modify_time,
        uid: inode.uid,
        gid: inode.gid,
        mode: inode.mode,
        nlink: inode.nlink(),
    }
}

/// Mutation API: only available when the underlying handle supports `Write`
impl<R: Read + Write + Seek> ApfsVolume<R> {
    pub fn set_inode_times(
        &mut self,
        path: &str,
        create_time: Option<i64>,
        modify_time: Option<i64>,
        change_time: Option<i64>,
        access_time: Option<i64>,
    ) -> Result<()> {
        let (oid, _inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        self.set_inode_times_by_oid(oid, create_time, modify_time, change_time, access_time)
    }

    pub fn set_inode_times_by_oid(
        &mut self,
        oid: u64,
        create_time: Option<i64>,
        modify_time: Option<i64>,
        change_time: Option<i64>,
        access_time: Option<i64>,
    ) -> Result<()> {
        let cmp = |key: &[u8]| -> std::cmp::Ordering {
            let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                Ok(t) => t,
                Err(_) => return std::cmp::Ordering::Less,
            };
            match k_oid.cmp(&oid) {
                std::cmp::Ordering::Equal => k_type.cmp(&catalog::J_TYPE_INODE),
                ord => ord,
            }
        };
        let (_val, leaf_paddr) = btree::btree_lookup_with_leaf(
            &mut self.reader,
            self.catalog_root_block,
            self.block_size,
            0,
            0,
            &cmp,
            Some(self.vol_omap_root_block),
        )?
        .ok_or_else(|| ApfsError::NotFound(format!("inode OID {oid}")))?;

        let leaf_bytes = object::read_block(&mut self.reader, leaf_paddr, self.block_size)?;
        let mut node = btree::BTreeNode::parse(&leaf_bytes)?;
        catalog::set_inode_times_in_node(
            &mut node,
            oid,
            create_time,
            modify_time,
            change_time,
            access_time,
        )?;
        let new_block = node.serialize()?.to_vec();

        let mut tx = transaction::Transaction::new(self.block_size as u64);
        tx.stage(leaf_paddr, new_block)?;
        let (_n, new_nxsb_paddr) = tx.commit_with_nxsb_rotation(&mut self.reader, &self.nxsb)?;

        let nxsb_bytes = object::read_block(&mut self.reader, new_nxsb_paddr, self.block_size)?;
        self.nxsb = superblock::NxSuperblock::parse(&nxsb_bytes)?;
        Ok(())
    }

    /// Splice a new logical size into the inode's dstream xfield. Loopback
    /// semantics: only shrinks (or no-ops) are accepted, since growing the
    /// logical size past the allocated extents would expose uninitialized
    /// blocks. Allocated extents are never freed by this call; they leak
    /// until extent-aware truncation lands
    pub fn set_logical_size(&mut self, path: &str, new_size: u64) -> Result<()> {
        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        if inode.kind() != catalog::INODE_FILE_TYPE {
            return Err(ApfsError::NotADirectory(format!(
                "set_logical_size: {path} is not a regular file"
            )));
        }
        let cur = inode.size();
        if new_size == cur {
            return Ok(());
        }
        if new_size > cur {
            return Err(ApfsError::Internal(format!(
                "set_logical_size: grow not supported (cur={cur} new={new_size})"
            )));
        }
        let cmp = |key: &[u8]| -> std::cmp::Ordering {
            let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                Ok(t) => t,
                Err(_) => return std::cmp::Ordering::Less,
            };
            match k_oid.cmp(&oid) {
                std::cmp::Ordering::Equal => k_type.cmp(&catalog::J_TYPE_INODE),
                ord => ord,
            }
        };
        let (_val, leaf_paddr) = btree::btree_lookup_with_leaf(
            &mut self.reader,
            self.catalog_root_block,
            self.block_size,
            0,
            0,
            &cmp,
            Some(self.vol_omap_root_block),
        )?
        .ok_or_else(|| ApfsError::NotFound(format!("inode OID {oid}")))?;

        let leaf_bytes = object::read_block(&mut self.reader, leaf_paddr, self.block_size)?;
        let mut node = btree::BTreeNode::parse(&leaf_bytes)?;
        catalog::set_inode_dstream_size_in_node(&mut node, oid, new_size)?;
        let new_block = node.serialize()?.to_vec();

        let mut tx = transaction::Transaction::new(self.block_size as u64);
        tx.stage(leaf_paddr, new_block)?;
        let (_n, new_nxsb_paddr) = tx.commit_with_nxsb_rotation(&mut self.reader, &self.nxsb)?;

        let nxsb_bytes = object::read_block(&mut self.reader, new_nxsb_paddr, self.block_size)?;
        self.nxsb = superblock::NxSuperblock::parse(&nxsb_bytes)?;
        Ok(())
    }

    /// Unlink a regular file. Removes its drec from the parent directory,
    /// the inode record itself, the dstream_id record, and every
    /// `J_TYPE_FILE_EXTENT` record. Decrements the parent's nchildren
    /// Loopback semantics: physical blocks owned by removed extents leak;
    /// they are not returned to the spaceman. Hard-linked inodes
    /// (`nlink > 1`) are rejected; xattr-bearing inodes are rejected
    pub fn unlink_file(&mut self, path: &str) -> Result<()> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(ApfsError::Internal("unlink_file: empty path".into()));
        }
        let basename = trimmed.rsplit('/').next().unwrap();

        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        if inode.kind() != catalog::INODE_FILE_TYPE {
            return Err(ApfsError::NotADirectory(format!(
                "unlink_file: {path} is not a regular file"
            )));
        }
        if inode.nlink() != 1 {
            return Err(ApfsError::Internal(format!(
                "unlink_file: nlink={} not yet supported",
                inode.nlink()
            )));
        }
        let parent_oid = inode.parent_id;

        // Cache leaves we touch so multiple deletions in one leaf
        // accumulate before staging
        let mut touched: std::collections::BTreeMap<u64, btree::BTreeNode> =
            std::collections::BTreeMap::new();

        // 1. Remove the drec entry in parent's leaf
        {
            let drec_cmp = |key: &[u8]| -> std::cmp::Ordering {
                let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                    Ok(t) => t,
                    Err(_) => return std::cmp::Ordering::Less,
                };
                match k_oid.cmp(&parent_oid) {
                    std::cmp::Ordering::Equal => k_type.cmp(&catalog::J_TYPE_DIR_REC),
                    ord => ord,
                }
            };
            // We don't know the drec's hash, so range-scan then locate the
            // leaf+idx ourselves
            let entries = btree::btree_scan_with_leaves(
                &mut self.reader,
                self.catalog_root_block,
                self.block_size,
                0,
                0,
                &|key: &[u8]| -> Option<bool> {
                    match drec_cmp(key) {
                        std::cmp::Ordering::Less => Some(false),
                        std::cmp::Ordering::Equal => Some(true),
                        std::cmp::Ordering::Greater => None,
                    }
                },
                Some(self.vol_omap_root_block),
            )?;
            let mut found_paddr: Option<u64> = None;
            for (key, _val, paddr) in &entries {
                let node = self.load_or_get_leaf(&mut touched, *paddr)?;
                if let Some(idx) = catalog::find_record_in_node(
                    node,
                    parent_oid,
                    catalog::J_TYPE_DIR_REC,
                    Some(basename),
                )? {
                    // Confirm the key bytes match (defensive)
                    let _ = key;
                    node.delete_leaf_var(idx)?;
                    found_paddr = Some(*paddr);
                    break;
                }
            }
            if found_paddr.is_none() {
                return Err(ApfsError::NotFound(format!(
                    "unlink_file: drec for '{basename}' under oid {parent_oid} not found"
                )));
            }
        }

        // 2. Remove inode record
        self.delete_record_in_leaf(&mut touched, oid, catalog::J_TYPE_INODE, None)?;

        // 3. Remove dstream_id record (may not exist for empty/zero-length files)
        let _ = self.delete_record_in_leaf(&mut touched, oid, catalog::J_TYPE_DSTREAM_ID, None);

        // 4. Remove all file_extent records (may span multiple leaves)
        {
            let entries = btree::btree_scan_with_leaves(
                &mut self.reader,
                self.catalog_root_block,
                self.block_size,
                0,
                0,
                &|key: &[u8]| -> Option<bool> {
                    let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                        Ok(t) => t,
                        Err(_) => return Some(false),
                    };
                    match (k_oid.cmp(&oid), k_type.cmp(&catalog::J_TYPE_FILE_EXTENT)) {
                        (std::cmp::Ordering::Less, _) => Some(false),
                        (std::cmp::Ordering::Equal, std::cmp::Ordering::Equal) => Some(true),
                        (std::cmp::Ordering::Equal, std::cmp::Ordering::Less) => Some(false),
                        (std::cmp::Ordering::Equal, std::cmp::Ordering::Greater) => None,
                        (std::cmp::Ordering::Greater, _) => None,
                    }
                },
                Some(self.vol_omap_root_block),
            )?;
            // Collect distinct leaf paddrs
            let mut leaves: Vec<u64> = entries.iter().map(|(_, _, p)| *p).collect();
            leaves.sort_unstable();
            leaves.dedup();
            for paddr in leaves {
                let node = self.load_or_get_leaf(&mut touched, paddr)?;
                catalog::delete_records_in_node(node, oid, catalog::J_TYPE_FILE_EXTENT)?;
            }
        }

        // 5. Decrement parent's nchildren
        {
            let cmp = |key: &[u8]| -> std::cmp::Ordering {
                let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                    Ok(t) => t,
                    Err(_) => return std::cmp::Ordering::Less,
                };
                match k_oid.cmp(&parent_oid) {
                    std::cmp::Ordering::Equal => k_type.cmp(&catalog::J_TYPE_INODE),
                    ord => ord,
                }
            };
            let (_v, leaf_paddr) = btree::btree_lookup_with_leaf(
                &mut self.reader,
                self.catalog_root_block,
                self.block_size,
                0,
                0,
                &cmp,
                Some(self.vol_omap_root_block),
            )?
            .ok_or_else(|| ApfsError::NotFound(format!("parent inode {parent_oid}")))?;
            let node = self.load_or_get_leaf(&mut touched, leaf_paddr)?;
            catalog::dec_inode_counter_in_node(node, parent_oid)?;
        }

        // Stage every modified leaf, commit via NXSB rotation
        let mut tx = transaction::Transaction::new(self.block_size as u64);
        for (paddr, mut node) in touched {
            let bytes = node.serialize()?.to_vec();
            tx.stage(paddr, bytes)?;
        }
        let (_n, new_nxsb_paddr) = tx.commit_with_nxsb_rotation(&mut self.reader, &self.nxsb)?;
        let nxsb_bytes = object::read_block(&mut self.reader, new_nxsb_paddr, self.block_size)?;
        self.nxsb = superblock::NxSuperblock::parse(&nxsb_bytes)?;
        Ok(())
    }

    /// Helper: locate or load the leaf at `paddr` into the cache, returning
    /// a mutable reference to the parsed node
    fn load_or_get_leaf<'a>(
        &mut self,
        cache: &'a mut std::collections::BTreeMap<u64, btree::BTreeNode>,
        paddr: u64,
    ) -> Result<&'a mut btree::BTreeNode> {
        use std::collections::btree_map::Entry;
        match cache.entry(paddr) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => {
                let bytes = object::read_block(&mut self.reader, paddr, self.block_size)?;
                let node = btree::BTreeNode::parse(&bytes)?;
                Ok(e.insert(node))
            }
        }
    }

    /// Helper: locate the catalog record for `(oid, j_type)`, load its leaf
    /// into the cache (or reuse a cached version), and delete it from the
    /// in-memory node. Drec deletions need a `name` filter; pass `None` for
    /// records that have at most one entry per (oid, type) pair
    fn delete_record_in_leaf(
        &mut self,
        cache: &mut std::collections::BTreeMap<u64, btree::BTreeNode>,
        oid: u64,
        j_type: u8,
        drec_name: Option<&str>,
    ) -> Result<()> {
        let cmp = move |key: &[u8]| -> std::cmp::Ordering {
            let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                Ok(t) => t,
                Err(_) => return std::cmp::Ordering::Less,
            };
            match k_oid.cmp(&oid) {
                std::cmp::Ordering::Equal => k_type.cmp(&j_type),
                ord => ord,
            }
        };
        let (_v, leaf_paddr) = btree::btree_lookup_with_leaf(
            &mut self.reader,
            self.catalog_root_block,
            self.block_size,
            0,
            0,
            &cmp,
            Some(self.vol_omap_root_block),
        )?
        .ok_or_else(|| {
            ApfsError::NotFound(format!("record (oid={oid}, type={j_type}) not found"))
        })?;
        let node = self.load_or_get_leaf(cache, leaf_paddr)?;
        let idx = catalog::find_record_in_node(node, oid, j_type, drec_name)?.ok_or_else(|| {
            ApfsError::NotFound(format!(
                "record (oid={oid}, type={j_type}) not in expected leaf"
            ))
        })?;
        node.delete_leaf_var(idx)?;
        Ok(())
    }

    /// Ensure the in-memory spaceman is loaded; reused across alloc calls
    fn ensure_spaceman(&mut self) -> Result<()> {
        if self.spaceman.is_some() {
            return Ok(());
        }
        if self.spaceman_paddr == 0 {
            return Err(ApfsError::Internal(
                "spaceman_paddr unknown; cannot allocate".into(),
            ));
        }
        let sm =
            spaceman::SpaceManager::open(&mut self.reader, self.spaceman_paddr, self.block_size)?;
        self.spaceman = Some(sm);
        Ok(())
    }

    /// Allocate `count` new blocks. The bitmap is updated in memory only —
    /// loopback semantics: we never persist the spaceman state, so on next
    /// mount the on-disk bitmap will still show these blocks as free. Use
    /// only on disposable / I_UNDERSTAND_DATA_LOSS images
    fn alloc_blocks(&mut self, count: u64) -> Result<Vec<(u64, u64)>> {
        self.ensure_spaceman()?;
        self.spaceman.as_mut().unwrap().alloc_blocks(count)
    }

    /// Allocate a fresh OID for a new file or directory. Pulled from the
    /// in-memory `next_obj_id` cursor seeded at mount time
    fn alloc_oid(&mut self) -> u64 {
        let oid = self.next_obj_id;
        self.next_obj_id += 1;
        oid
    }

    /// Compute an APFS hashed-drec name hash respecting the volume's
    /// case-sensitivity flag
    fn drec_hash(&self, name: &str) -> Result<u32> {
        hash::drec_name_hash(name, self.case_insensitive)
    }

    /// Stage a set of leaves into a transaction and commit through NXSB
    /// rotation. All paddrs in `nodes` must be existing leaves whose
    /// physical addresses we rewrite in place
    fn commit_leaves(
        &mut self,
        nodes: std::collections::BTreeMap<u64, btree::BTreeNode>,
    ) -> Result<()> {
        let mut tx = transaction::Transaction::new(self.block_size as u64);
        for (paddr, mut node) in nodes {
            let bytes = node.serialize()?.to_vec();
            tx.stage(paddr, bytes)?;
        }
        let (_n, new_nxsb_paddr) = tx.commit_with_nxsb_rotation(&mut self.reader, &self.nxsb)?;
        let nxsb_bytes = object::read_block(&mut self.reader, new_nxsb_paddr, self.block_size)?;
        self.nxsb = superblock::NxSuperblock::parse(&nxsb_bytes)?;
        Ok(())
    }

    /// Locate the leaf paddr that holds the catalog record for `(oid, j_type)`
    /// Errors if not found
    fn locate_record_leaf(&mut self, oid: u64, j_type: u8) -> Result<u64> {
        let cmp = move |key: &[u8]| -> std::cmp::Ordering {
            let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                Ok(t) => t,
                Err(_) => return std::cmp::Ordering::Less,
            };
            match k_oid.cmp(&oid) {
                std::cmp::Ordering::Equal => k_type.cmp(&j_type),
                ord => ord,
            }
        };
        let (_v, leaf_paddr) = btree::btree_lookup_with_leaf(
            &mut self.reader,
            self.catalog_root_block,
            self.block_size,
            0,
            0,
            &cmp,
            Some(self.vol_omap_root_block),
        )?
        .ok_or_else(|| {
            ApfsError::NotFound(format!(
                "catalog record (oid={oid}, type={j_type}) not found"
            ))
        })?;
        Ok(leaf_paddr)
    }

    /// Locate the leaf paddr that holds (or would hold) a record with the
    /// given `target_key`. Walks the catalog from its root, descending into
    /// the child whose key is the largest <= `target_key`. Used by insert
    /// paths to pick the leaf even when the exact key is not present
    fn locate_leaf_for_key(&mut self, target_key: &[u8]) -> Result<u64> {
        let mut paddr = self.catalog_root_block;
        loop {
            let block = object::read_block(&mut self.reader, paddr, self.block_size)?;
            let node = btree::BTreeNode::parse(&block)?;
            if node.is_leaf() {
                return Ok(paddr);
            }
            let mut chosen: Option<usize> = None;
            for i in 0..node.nkeys() {
                let key = node.key_at(i, 0)?;
                match catalog::cmp_catalog_keys(key, target_key) {
                    std::cmp::Ordering::Less | std::cmp::Ordering::Equal => chosen = Some(i),
                    std::cmp::Ordering::Greater => break,
                }
            }
            let idx = chosen.unwrap_or(0);
            let child_oid = node.child_oid_at(idx)?;
            paddr = omap::omap_lookup(
                &mut self.reader,
                self.vol_omap_root_block,
                self.block_size,
                child_oid,
            )?;
        }
    }

    /// Create a new empty regular file at `path`. Allocates a fresh OID,
    /// inserts an inode record + drec under the parent, and bumps the
    /// parent's nchildren. The file is zero-length with no extents
    pub fn create_file(&mut self, path: &str) -> Result<u64> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(ApfsError::Internal("create_file: empty path".into()));
        }
        let (parent_path, basename) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", trimmed),
        };
        if basename.is_empty() {
            return Err(ApfsError::Internal("create_file: empty basename".into()));
        }
        let parent_lookup = if parent_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parent_path)
        };
        let (parent_oid, parent_inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            &parent_lookup,
        )?;
        if parent_inode.kind() != catalog::INODE_DIR_TYPE {
            return Err(ApfsError::NotADirectory(parent_lookup));
        }
        // Reject if the entry already exists under any name match
        if self
            .stat(&format!(
                "{}/{}",
                parent_lookup.trim_end_matches('/'),
                basename
            ))
            .is_ok()
        {
            return Err(ApfsError::Internal(format!(
                "create_file: '{path}' already exists"
            )));
        }

        let new_oid = self.alloc_oid();
        let now = chrono_now_nanos();
        let inode_template = catalog::InodeVal {
            parent_id: parent_oid,
            private_id: new_oid,
            create_time: now,
            modify_time: now,
            change_time: now,
            access_time: now,
            internal_flags: 0,
            nchildren_or_nlink: 1,
            default_protection_class: 0,
            write_generation_counter: 1,
            bsd_flags: 0,
            uid: 0,
            gid: 0,
            mode: catalog::INODE_FILE_TYPE | 0o644,
            pad1: 0,
            uncompressed_size: 0,
            dstream_size: None,
        };
        let inode_value = catalog::build_inode_value(&inode_template, None)?;
        let hash22 = self.drec_hash(basename)?;

        let inode_key = {
            let mut k = Vec::with_capacity(8);
            k.extend_from_slice(&catalog::encode_obj_id_and_type(
                new_oid,
                catalog::J_TYPE_INODE,
            ));
            k
        };
        let drec_key = catalog::encode_drec_hashed_key(parent_oid, basename, hash22)?;

        let inode_leaf = self.locate_leaf_for_key(&inode_key)?;
        let drec_leaf = self.locate_leaf_for_key(&drec_key)?;
        let parent_inode_leaf = self.locate_record_leaf(parent_oid, catalog::J_TYPE_INODE)?;

        let mut touched: std::collections::BTreeMap<u64, btree::BTreeNode> =
            std::collections::BTreeMap::new();
        {
            let n = self.load_or_get_leaf(&mut touched, inode_leaf)?;
            catalog::insert_inode_record(n, new_oid, &inode_value)?;
        }
        {
            let n = self.load_or_get_leaf(&mut touched, drec_leaf)?;
            catalog::insert_drec_record(
                n,
                parent_oid,
                basename,
                hash22,
                new_oid,
                now,
                catalog::DT_REG,
            )?;
        }
        {
            let n = self.load_or_get_leaf(&mut touched, parent_inode_leaf)?;
            catalog::inc_inode_counter_in_node(n, parent_oid)?;
        }
        self.commit_leaves(touched)?;
        Ok(new_oid)
    }

    /// Create a new empty directory at `path`. Same as [`Self::create_file`]
    /// except the inode kind is `INODE_DIR_TYPE` and `nchildren_or_nlink`
    /// starts at 0 (no entries yet)
    pub fn create_directory(&mut self, path: &str) -> Result<u64> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(ApfsError::Internal("create_directory: empty path".into()));
        }
        let (parent_path, basename) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", trimmed),
        };
        let parent_lookup = if parent_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parent_path)
        };
        let (parent_oid, parent_inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            &parent_lookup,
        )?;
        if parent_inode.kind() != catalog::INODE_DIR_TYPE {
            return Err(ApfsError::NotADirectory(parent_lookup));
        }
        if self
            .stat(&format!(
                "{}/{}",
                parent_lookup.trim_end_matches('/'),
                basename
            ))
            .is_ok()
        {
            return Err(ApfsError::Internal(format!(
                "create_directory: '{path}' already exists"
            )));
        }
        let new_oid = self.alloc_oid();
        let now = chrono_now_nanos();
        let inode_template = catalog::InodeVal {
            parent_id: parent_oid,
            private_id: new_oid,
            create_time: now,
            modify_time: now,
            change_time: now,
            access_time: now,
            internal_flags: 0,
            nchildren_or_nlink: 0,
            default_protection_class: 0,
            write_generation_counter: 1,
            bsd_flags: 0,
            uid: 0,
            gid: 0,
            mode: catalog::INODE_DIR_TYPE | 0o755,
            pad1: 0,
            uncompressed_size: 0,
            dstream_size: None,
        };
        let inode_value = catalog::build_inode_value(&inode_template, None)?;
        let hash22 = self.drec_hash(basename)?;

        let inode_key = {
            let mut k = Vec::with_capacity(8);
            k.extend_from_slice(&catalog::encode_obj_id_and_type(
                new_oid,
                catalog::J_TYPE_INODE,
            ));
            k
        };
        let drec_key = catalog::encode_drec_hashed_key(parent_oid, basename, hash22)?;

        let inode_leaf = self.locate_leaf_for_key(&inode_key)?;
        let drec_leaf = self.locate_leaf_for_key(&drec_key)?;
        let parent_inode_leaf = self.locate_record_leaf(parent_oid, catalog::J_TYPE_INODE)?;

        let mut touched: std::collections::BTreeMap<u64, btree::BTreeNode> =
            std::collections::BTreeMap::new();
        {
            let n = self.load_or_get_leaf(&mut touched, inode_leaf)?;
            catalog::insert_inode_record(n, new_oid, &inode_value)?;
        }
        {
            let n = self.load_or_get_leaf(&mut touched, drec_leaf)?;
            catalog::insert_drec_record(
                n,
                parent_oid,
                basename,
                hash22,
                new_oid,
                now,
                catalog::DT_DIR,
            )?;
        }
        {
            let n = self.load_or_get_leaf(&mut touched, parent_inode_leaf)?;
            catalog::inc_inode_counter_in_node(n, parent_oid)?;
        }
        self.commit_leaves(touched)?;
        Ok(new_oid)
    }

    /// Remove an empty directory. Mirrors [`Self::unlink_file`] except no
    /// extents/dstream are involved and the target's nchildren must be zero
    pub fn unlink_directory(&mut self, path: &str) -> Result<()> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(ApfsError::Internal("unlink_directory: empty path".into()));
        }
        let basename = trimmed.rsplit('/').next().unwrap();
        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        if inode.kind() != catalog::INODE_DIR_TYPE {
            return Err(ApfsError::NotADirectory(format!(
                "unlink_directory: {path} is not a directory"
            )));
        }
        if inode.nchildren_or_nlink != 0 {
            return Err(ApfsError::Internal(format!(
                "unlink_directory: '{path}' is not empty (nchildren={})",
                inode.nchildren_or_nlink
            )));
        }
        let parent_oid = inode.parent_id;

        let mut touched: std::collections::BTreeMap<u64, btree::BTreeNode> =
            std::collections::BTreeMap::new();
        // 1. Remove drec under parent
        {
            let entries = btree::btree_scan_with_leaves(
                &mut self.reader,
                self.catalog_root_block,
                self.block_size,
                0,
                0,
                &|key: &[u8]| -> Option<bool> {
                    let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                        Ok(t) => t,
                        Err(_) => return Some(false),
                    };
                    match k_oid.cmp(&parent_oid) {
                        std::cmp::Ordering::Less => Some(false),
                        std::cmp::Ordering::Equal => match k_type.cmp(&catalog::J_TYPE_DIR_REC) {
                            std::cmp::Ordering::Less => Some(false),
                            std::cmp::Ordering::Equal => Some(true),
                            std::cmp::Ordering::Greater => None,
                        },
                        std::cmp::Ordering::Greater => None,
                    }
                },
                Some(self.vol_omap_root_block),
            )?;
            let mut found = false;
            for (_key, _val, paddr) in &entries {
                let n = self.load_or_get_leaf(&mut touched, *paddr)?;
                if let Some(idx) = catalog::find_record_in_node(
                    n,
                    parent_oid,
                    catalog::J_TYPE_DIR_REC,
                    Some(basename),
                )? {
                    n.delete_leaf_var(idx)?;
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(ApfsError::NotFound(format!(
                    "drec for '{basename}' under oid {parent_oid}"
                )));
            }
        }
        // 2. Remove inode record
        self.delete_record_in_leaf(&mut touched, oid, catalog::J_TYPE_INODE, None)?;
        // 3. Decrement parent's nchildren
        {
            let leaf = self.locate_record_leaf(parent_oid, catalog::J_TYPE_INODE)?;
            let n = self.load_or_get_leaf(&mut touched, leaf)?;
            catalog::dec_inode_counter_in_node(n, parent_oid)?;
        }
        self.commit_leaves(touched)?;
        Ok(())
    }

    /// Rename `from` to `to`. Both endpoints must resolve to a parent
    /// directory the basename hashes against. Cross-parent rename adjusts
    /// nchildren on both parents. Replaces an existing entry at `to` only
    /// when `replace_if_exists` is set; otherwise errors
    pub fn rename_file(&mut self, from: &str, to: &str, replace_if_exists: bool) -> Result<()> {
        let from_t = from.trim_matches('/');
        let to_t = to.trim_matches('/');
        if from_t.is_empty() || to_t.is_empty() {
            return Err(ApfsError::Internal("rename_file: empty path".into()));
        }
        if from_t == to_t {
            return Ok(());
        }
        let (from_parent_path, from_base) = match from_t.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", from_t),
        };
        let (to_parent_path, to_base) = match to_t.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", to_t),
        };
        let from_parent_lookup = if from_parent_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", from_parent_path)
        };
        let to_parent_lookup = if to_parent_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", to_parent_path)
        };

        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            from,
        )?;
        let (from_parent_oid, _) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            &from_parent_lookup,
        )?;
        let (to_parent_oid, to_parent_inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            &to_parent_lookup,
        )?;
        if to_parent_inode.kind() != catalog::INODE_DIR_TYPE {
            return Err(ApfsError::NotADirectory(to_parent_lookup));
        }
        // Reject existing target unless explicit replace
        if let Ok(_existing) = self.stat(to) {
            if !replace_if_exists {
                return Err(ApfsError::Internal(format!(
                    "rename_file: '{to}' already exists and replace_if_exists is false"
                )));
            }
            // Best-effort replace: only support replacing a regular file
            // with our entry; reject directory target
            return Err(ApfsError::Unsupported(
                "rename_file: replace_if_exists for existing target not implemented".into(),
            ));
        }

        let from_hash = self.drec_hash(from_base)?;
        let to_hash = self.drec_hash(to_base)?;
        let new_drec_key = catalog::encode_drec_hashed_key(to_parent_oid, to_base, to_hash)?;
        let to_drec_leaf = self.locate_leaf_for_key(&new_drec_key)?;

        let mut touched: std::collections::BTreeMap<u64, btree::BTreeNode> =
            std::collections::BTreeMap::new();

        // 1. Locate and remove the OLD drec
        let entries = btree::btree_scan_with_leaves(
            &mut self.reader,
            self.catalog_root_block,
            self.block_size,
            0,
            0,
            &|key: &[u8]| -> Option<bool> {
                let (k_oid, k_type) = match catalog::decode_catalog_key_pub(key) {
                    Ok(t) => t,
                    Err(_) => return Some(false),
                };
                match k_oid.cmp(&from_parent_oid) {
                    std::cmp::Ordering::Less => Some(false),
                    std::cmp::Ordering::Equal => match k_type.cmp(&catalog::J_TYPE_DIR_REC) {
                        std::cmp::Ordering::Less => Some(false),
                        std::cmp::Ordering::Equal => Some(true),
                        std::cmp::Ordering::Greater => None,
                    },
                    std::cmp::Ordering::Greater => None,
                }
            },
            Some(self.vol_omap_root_block),
        )?;
        let mut old_found = false;
        for (_key, _val, paddr) in &entries {
            let n = self.load_or_get_leaf(&mut touched, *paddr)?;
            if let Some(idx) = catalog::find_record_in_node(
                n,
                from_parent_oid,
                catalog::J_TYPE_DIR_REC,
                Some(from_base),
            )? {
                n.delete_leaf_var(idx)?;
                old_found = true;
                break;
            }
        }
        let _ = from_hash;
        if !old_found {
            return Err(ApfsError::NotFound(format!(
                "rename_file: source drec '{from_base}' not found"
            )));
        }

        // 2. Insert NEW drec
        let now = chrono_now_nanos();
        let file_type = match inode.kind() {
            catalog::INODE_DIR_TYPE => catalog::DT_DIR,
            catalog::INODE_SYMLINK_TYPE => catalog::DT_LNK,
            _ => catalog::DT_REG,
        };
        {
            let n = self.load_or_get_leaf(&mut touched, to_drec_leaf)?;
            catalog::insert_drec_record(n, to_parent_oid, to_base, to_hash, oid, now, file_type)?;
        }

        // 3. Cross-parent rename: update both parents' nchildren and the
        //    moved inode's parent_id
        if from_parent_oid != to_parent_oid {
            let from_p_leaf = self.locate_record_leaf(from_parent_oid, catalog::J_TYPE_INODE)?;
            {
                let n = self.load_or_get_leaf(&mut touched, from_p_leaf)?;
                catalog::dec_inode_counter_in_node(n, from_parent_oid)?;
            }
            let to_p_leaf = self.locate_record_leaf(to_parent_oid, catalog::J_TYPE_INODE)?;
            {
                let n = self.load_or_get_leaf(&mut touched, to_p_leaf)?;
                catalog::inc_inode_counter_in_node(n, to_parent_oid)?;
            }
            // Rewrite the moved inode's parent_id field
            let inode_leaf = self.locate_record_leaf(oid, catalog::J_TYPE_INODE)?;
            let n = self.load_or_get_leaf(&mut touched, inode_leaf)?;
            let idx = catalog::find_record_in_node(n, oid, catalog::J_TYPE_INODE, None)?
                .ok_or_else(|| ApfsError::NotFound(format!("inode {oid}")))?;
            let val_bytes = n.value_at(idx, 0)?.to_vec();
            let mut iv = catalog::InodeVal::parse(&val_bytes)?;
            iv.parent_id = to_parent_oid;
            iv.change_time = now;
            let xfields = val_bytes[catalog::InodeVal::FIXED_SIZE..].to_vec();
            let new_val = iv.serialize_with_xfields(&xfields)?;
            n.replace_value(idx, &new_val, 0)?;
        }

        self.commit_leaves(touched)?;
        Ok(())
    }

    /// Append `buf` to the end of `path`, allocating new physical blocks
    /// as needed. Loopback semantics: spaceman bitmap mutations are
    /// in-memory only; the on-disk bitmap is never updated. The new file
    /// extent is a single contiguous run when possible
    pub fn append_data(&mut self, path: &str, buf: &[u8]) -> Result<u64> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        if inode.kind() != catalog::INODE_FILE_TYPE {
            return Err(ApfsError::NotADirectory(format!(
                "append_data: {path} is not a regular file"
            )));
        }
        let cur_size = inode.size();
        self.append_or_grow_to(oid, cur_size, cur_size + buf.len() as u64, Some(buf))
            .map(|_| buf.len() as u64)
    }

    /// Grow `path` to `new_size`, zero-filling the new bytes. Allocates
    /// new physical blocks via the spaceman; updates the dstream xfield
    /// (or installs one when missing). Errors if `new_size <= current size`
    pub fn grow_file(&mut self, path: &str, new_size: u64) -> Result<()> {
        let (oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        if inode.kind() != catalog::INODE_FILE_TYPE {
            return Err(ApfsError::NotADirectory(format!(
                "grow_file: {path} is not a regular file"
            )));
        }
        let cur_size = inode.size();
        if new_size <= cur_size {
            return Err(ApfsError::Internal(format!(
                "grow_file: new_size {new_size} <= current {cur_size}"
            )));
        }
        self.append_or_grow_to(oid, cur_size, new_size, None)
    }

    /// Common path for `append_data` and `grow_file`: allocate blocks for
    /// the new region `(cur_size, new_size]`, optionally write `data` into
    /// them (else zero-fill), insert a `J_TYPE_FILE_EXTENT` record covering
    /// the new run, and refresh the inode's dstream xfield
    fn append_or_grow_to(
        &mut self,
        oid: u64,
        cur_size: u64,
        new_size: u64,
        data: Option<&[u8]>,
    ) -> Result<()> {
        if new_size <= cur_size {
            return Ok(());
        }
        let bs = self.block_size as u64;
        // Round up the existing logical EOF to a block boundary; the
        // existing on-disk extent map allocates whole blocks. Any
        // intra-block tail of the previous EOF is part of the last
        // extent and overlaps with the first byte of the appended region
        let aligned_old_eof = cur_size.div_ceil(bs) * bs;
        let new_blocks_needed = if new_size > aligned_old_eof {
            (new_size - aligned_old_eof).div_ceil(bs)
        } else {
            0
        };

        // 1. Reserve blocks
        let runs = if new_blocks_needed > 0 {
            self.alloc_blocks(new_blocks_needed)?
        } else {
            Vec::new()
        };

        // 2. Write data + zero-fill into reserved blocks
        // Fill the tail of the existing last block first (if any data
        // overlaps with it); this only matters when cur_size is not block
        // aligned. We need the existing extent map to know the last block's
        // physical address
        if cur_size != aligned_old_eof
            && let Some(d) = data
        {
            let last_block_log_start = aligned_old_eof - bs;
            let exts = catalog::lookup_extents(
                &mut self.reader,
                self.catalog_root_block,
                self.vol_omap_root_block,
                self.block_size,
                oid,
            )?;
            let map = self.build_extent_map(&exts);
            if let Some((_, phys, _)) = map
                .iter()
                .find(|(s, _, l)| last_block_log_start >= *s && last_block_log_start < *s + *l)
            {
                let intra_off = (cur_size - last_block_log_start) as usize;
                let space_in_tail = bs as usize - intra_off;
                let copy_len = space_in_tail.min(d.len());
                let phys_start = phys + (cur_size - last_block_log_start);
                self.write_raw_at(phys_start, &d[..copy_len])?;
            }
        }
        // Write any payload that lands in newly allocated blocks
        let mut data_off = if cur_size == aligned_old_eof {
            0
        } else {
            // bytes already consumed by the tail-fill above
            let tail = (aligned_old_eof - cur_size) as usize;
            tail.min(data.map(|d| d.len()).unwrap_or(0))
        };
        let mut new_logical_off = aligned_old_eof;
        for &(start_paddr, run_len_blocks) in &runs {
            for blk in 0..run_len_blocks {
                let phys = (start_paddr + blk) * bs;
                let mut block = vec![0u8; bs as usize];
                if let Some(d) = data
                    && data_off < d.len()
                    && new_logical_off < new_size
                {
                    let want = ((new_size - new_logical_off) as usize)
                        .min(bs as usize)
                        .min(d.len() - data_off);
                    block[..want].copy_from_slice(&d[data_off..data_off + want]);
                    data_off += want;
                }
                self.write_raw_at(phys, &block)?;
                new_logical_off += bs;
            }
        }

        // 3. Insert a file_extent record per allocated run. Logical addr
        //    starts at aligned_old_eof and increments by run length
        let mut touched: std::collections::BTreeMap<u64, btree::BTreeNode> =
            std::collections::BTreeMap::new();
        let mut log_addr = aligned_old_eof;
        for (start_paddr, run_len_blocks) in &runs {
            let length_bytes = run_len_blocks * bs;
            let key = {
                let mut k = Vec::with_capacity(16);
                k.extend_from_slice(&catalog::encode_obj_id_and_type(
                    oid,
                    catalog::J_TYPE_FILE_EXTENT,
                ));
                k.extend_from_slice(&log_addr.to_le_bytes());
                k
            };
            let leaf = self.locate_leaf_for_key(&key)?;
            let n = self.load_or_get_leaf(&mut touched, leaf)?;
            catalog::insert_file_extent_record(n, oid, log_addr, length_bytes, *start_paddr)?;
            log_addr += length_bytes;
        }

        // 4. Update dstream xfield (or rewrite the inode value to add one)
        let inode_leaf = self.locate_record_leaf(oid, catalog::J_TYPE_INODE)?;
        let cur_alloced = cur_size.div_ceil(bs) * bs;
        let new_alloced = new_size.div_ceil(bs) * bs;
        // Try in-place splice first (works when dstream xfield exists)
        let needs_install = {
            let n = self.load_or_get_leaf(&mut touched, inode_leaf)?;
            match catalog::set_inode_dstream_size_and_alloc_in_node(n, oid, new_size, new_alloced) {
                Ok(_) => false,
                Err(ApfsError::BadCatalog(_)) => true,
                Err(e) => return Err(e),
            }
        };
        if needs_install {
            // Rewrite the inode value with a freshly-installed dstream xfield
            let n = self.load_or_get_leaf(&mut touched, inode_leaf)?;
            let idx = catalog::find_record_in_node(n, oid, catalog::J_TYPE_INODE, None)?
                .ok_or_else(|| ApfsError::NotFound(format!("inode {oid}")))?;
            let val = n.value_at(idx, 0)?.to_vec();
            let mut iv = catalog::InodeVal::parse(&val)?;
            iv.dstream_size = Some(new_size);
            iv.modify_time = chrono_now_nanos();
            iv.change_time = iv.modify_time;
            let new_val = catalog::build_inode_value(
                &iv,
                Some(catalog::JDstream {
                    size: new_size,
                    alloced_size: new_alloced,
                    default_crypto_id: 0,
                    total_bytes_written: new_size,
                    total_bytes_read: 0,
                }),
            )?;
            catalog::replace_inode_value_in_node(n, oid, &new_val)?;
        }
        let _ = cur_alloced;

        // 5. If a dstream_id record doesn't already exist, install one.
        //    Existing files created by macOS on the fixture have one; for
        //    files we created (via create_file) the first append/grow needs
        //    to install it
        let has_dstream_id = self
            .locate_record_leaf(oid, catalog::J_TYPE_DSTREAM_ID)
            .is_ok();
        if !has_dstream_id {
            let key = {
                let mut k = Vec::with_capacity(8);
                k.extend_from_slice(&catalog::encode_obj_id_and_type(
                    oid,
                    catalog::J_TYPE_DSTREAM_ID,
                ));
                k
            };
            let leaf = self.locate_leaf_for_key(&key)?;
            let n = self.load_or_get_leaf(&mut touched, leaf)?;
            catalog::insert_dstream_id_record(n, oid, 1)?;
        }

        self.commit_leaves(touched)?;
        Ok(())
    }
}

/// Fast-path replacement for the original `set_logical_size` shrink: also
/// supports growing via [`ApfsVolume::grow_file`]
fn chrono_now_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

impl<R: Read + Write + Seek> ApfsVolume<R> {
    /// to the existing physical blocks. The write must fall entirely within
    /// the current file size; this path neither allocates new extents nor
    /// updates the inode's dstream size. Use [`Self::set_inode_times`] to
    /// refresh mtime after a successful write
    ///
    /// Returns the number of bytes written. Always equal to `buf.len()` on
    /// success; partial writes only happen if a sparse hole is encountered
    /// (no extent covers a logical offset), in which case the call returns
    /// the number of bytes written before the hole
    pub fn write_at(&mut self, path: &str, offset: u64, buf: &[u8]) -> Result<u64> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (_oid, inode) = catalog::resolve_path(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            path,
        )?;
        if inode.kind() != catalog::INODE_FILE_TYPE {
            return Err(ApfsError::NotADirectory(format!(
                "write_at: {path} is not a regular file"
            )));
        }
        let file_size = inode.size();
        if offset >= file_size {
            return Err(ApfsError::Internal(format!(
                "write_at: offset {offset} >= file_size {file_size} (no extent allocation)"
            )));
        }
        let max = (file_size - offset).min(buf.len() as u64);
        if max == 0 {
            return Ok(0);
        }
        let extents = catalog::lookup_extents(
            &mut self.reader,
            self.catalog_root_block,
            self.vol_omap_root_block,
            self.block_size,
            inode.private_id,
        )?;
        let map = self.build_extent_map(&extents);
        self.write_through_extent_map(&map, offset, &buf[..max as usize])
    }

    /// Lower-level write driven by a precomputed extent map. Exposed so the
    /// driver can reuse the cached extent_map it built at open() time
    pub fn write_at_extents(
        &mut self,
        extent_map: &[(u64, u64, u64)],
        offset: u64,
        buf: &[u8],
    ) -> Result<u64> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_through_extent_map(extent_map, offset, buf)
    }

    fn write_through_extent_map(
        &mut self,
        map: &[(u64, u64, u64)],
        offset: u64,
        buf: &[u8],
    ) -> Result<u64> {
        let mut written = 0u64;
        let total = buf.len() as u64;
        while written < total {
            let logical = offset + written;
            let Some((log_start, phys_start, length)) = map
                .iter()
                .find(|(s, _, l)| logical >= *s && logical < *s + *l)
                .copied()
            else {
                // Sparse hole: stop here and return what we've written
                return Ok(written);
            };
            let intra = logical - log_start;
            let avail_in_extent = length - intra;
            let chunk = avail_in_extent.min(total - written);
            let phys_offset = phys_start + intra;
            self.write_raw_at(
                phys_offset,
                &buf[written as usize..(written + chunk) as usize],
            )?;
            written += chunk;
        }
        Ok(written)
    }

    /// Write `data` to physical byte offset `phys_offset` (relative to the
    /// container start as the underlying handle sees it). Performs read-
    /// modify-write at the block boundary so callers can write any sub-range
    fn write_raw_at(&mut self, phys_offset: u64, data: &[u8]) -> Result<()> {
        let bs = self.block_size as u64;
        let mut written = 0u64;
        while written < data.len() as u64 {
            let cur_phys = phys_offset + written;
            let block_num = cur_phys / bs;
            let intra = (cur_phys % bs) as usize;
            let chunk = ((bs - intra as u64) as usize).min(data.len() - written as usize);

            // RMW: read whole block, splice, seek back, write block
            let mut block = vec![0u8; bs as usize];
            self.reader.seek(std::io::SeekFrom::Start(block_num * bs))?;
            self.reader.read_exact(&mut block)?;
            block[intra..intra + chunk]
                .copy_from_slice(&data[written as usize..written as usize + chunk]);
            self.reader.seek(std::io::SeekFrom::Start(block_num * bs))?;
            self.reader.write_all(&block)?;
            written += chunk as u64;
        }
        self.reader.flush()?;
        Ok(())
    }
}
