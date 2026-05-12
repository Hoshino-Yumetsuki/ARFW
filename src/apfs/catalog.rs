//! APFS catalog (`fstree`) helpers
//!
//! The catalog is a B-tree of variable-sized `(j_key_t, j_val_t)` pairs that
//! describes inodes, directory records, file extents, extended attributes,
//! and so on. Keys carry both the object identifier (low 60 bits) and the
//! record type (top 4 bits, `j_obj_types`)
//!
//! This module covers the subset ARFW needs: inode parsing/serialisation,
//! directory record parsing, file-extent parsing, and lookup/scan routines
//! built on top of [`crate::apfs::btree`]
use crate::apfs::btree::{self, BTreeNode};
use crate::apfs::error::{ApfsError, Result};
use crate::apfs::{DirEntry, EntryKind};
use std::cmp::Ordering;
use std::io::{Read, Seek};

// ---------------------------------------------------------------------------
// j_obj_types: top 4 bits of `j_key_t.obj_id_and_type`
// ---------------------------------------------------------------------------
pub const J_TYPE_SNAP_METADATA: u8 = 1;
pub const J_TYPE_EXTENT: u8 = 2;
pub const J_TYPE_INODE: u8 = 3;
pub const J_TYPE_XATTR: u8 = 4;
pub const J_TYPE_SIBLING_LINK: u8 = 5;
pub const J_TYPE_DSTREAM_ID: u8 = 6;
pub const J_TYPE_CRYPTO_STATE: u8 = 7;
pub const J_TYPE_FILE_EXTENT: u8 = 8;
pub const J_TYPE_DIR_REC: u8 = 9;
pub const J_TYPE_DIR_STATS: u8 = 10;
pub const J_TYPE_SNAP_NAME: u8 = 11;
pub const J_TYPE_SIBLING_MAP: u8 = 12;

/// Well-known OIDs
pub const ROOT_DIR_PARENT: u64 = 1;
pub const ROOT_DIR_RECORD: u64 = 2;

/// BSD `mode` masks identifying inode kind
pub const INODE_DIR_TYPE: u16 = 0o040000;
pub const INODE_FILE_TYPE: u16 = 0o100000;
pub const INODE_SYMLINK_TYPE: u16 = 0o120000;

/// Extended-field tag (`INO_EXT_TYPE_*`) that carries an `j_dstream_t` blob
const INO_EXT_TYPE_DSTREAM: u8 = 8;

/// `dirent.h`-style file types embedded in `j_drec_val_t.flags`
pub const DT_REG: u16 = 8;
pub const DT_DIR: u16 = 4;
pub const DT_LNK: u16 = 10;

/// Pack `(oid, j_type)` into the 8-byte `obj_id_and_type` field
pub fn encode_obj_id_and_type(oid: u64, j_type: u8) -> [u8; 8] {
    let raw = (oid & 0x0FFF_FFFF_FFFF_FFFF) | ((j_type as u64) << 60);
    raw.to_le_bytes()
}

/// Compare two raw catalog keys per APFS rules: by `(oid, j_type)` first
/// (the standard `compare_fs_keys` semantics; oid in low 60 bits compared
/// independently from j_type in the high 4 bits), then by the per-record
/// secondary key (drec name+hash, file_extent logical_addr, xattr name)
pub fn cmp_catalog_keys(a: &[u8], b: &[u8]) -> Ordering {
    let (a_oid, a_type) = match decode_catalog_key(a) {
        Ok(t) => t,
        Err(_) => return Ordering::Equal,
    };
    let (b_oid, b_type) = match decode_catalog_key(b) {
        Ok(t) => t,
        Err(_) => return Ordering::Equal,
    };
    match a_oid.cmp(&b_oid) {
        Ordering::Equal => {}
        ord => return ord,
    }
    match a_type.cmp(&b_type) {
        Ordering::Equal => {}
        ord => return ord,
    }
    match a_type {
        J_TYPE_DIR_REC => {
            // Hashed drec subkey: (hash, name)
            let hash_a = if a.len() >= 12 { rd_u32(a, 8) >> 10 } else { 0 };
            let hash_b = if b.len() >= 12 { rd_u32(b, 8) >> 10 } else { 0 };
            match hash_a.cmp(&hash_b) {
                Ordering::Equal => a.get(12..).cmp(&b.get(12..)),
                ord => ord,
            }
        }
        J_TYPE_FILE_EXTENT => {
            // Subkey: 8-byte logical_addr after the 8-byte header
            let la = if a.len() >= 16 { rd_u64(a, 8) } else { 0 };
            let lb = if b.len() >= 16 { rd_u64(b, 8) } else { 0 };
            la.cmp(&lb)
        }
        J_TYPE_XATTR => a.get(8..).cmp(&b.get(8..)),
        _ => Ordering::Equal,
    }
}


// ---------------------------------------------------------------------------
// Tiny LE helpers: keep this crate dependency-free
// ---------------------------------------------------------------------------
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd_i32(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn rd_i64(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// j_inode_val_t
// ---------------------------------------------------------------------------

/// Decoded inode value (fixed prefix + dstream xfield, if present)
#[derive(Debug, Clone)]
pub struct InodeVal {
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: i64,
    pub modify_time: i64,
    pub change_time: i64,
    pub access_time: i64,
    pub internal_flags: u64,
    pub nchildren_or_nlink: i32,
    pub default_protection_class: u32,
    pub write_generation_counter: u32,
    pub bsd_flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub pad1: u16,
    pub uncompressed_size: u64,
    /// Logical file size from the dstream xfield, if the inode carries one
    pub dstream_size: Option<u64>,
}

impl InodeVal {
    /// Fixed on-disk size of `j_inode_val_t` (before xfields)
    pub const FIXED_SIZE: usize = 92;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "inode value too short: {} bytes",
                data.len()
            )));
        }
        Ok(Self {
            parent_id: rd_u64(data, 0),
            private_id: rd_u64(data, 8),
            create_time: rd_i64(data, 16),
            modify_time: rd_i64(data, 24),
            change_time: rd_i64(data, 32),
            access_time: rd_i64(data, 40),
            internal_flags: rd_u64(data, 48),
            nchildren_or_nlink: rd_i32(data, 56),
            default_protection_class: rd_u32(data, 60),
            write_generation_counter: rd_u32(data, 64),
            bsd_flags: rd_u32(data, 68),
            uid: rd_u32(data, 72),
            gid: rd_u32(data, 76),
            mode: rd_u16(data, 80),
            pad1: rd_u16(data, 82),
            uncompressed_size: rd_u64(data, 84),
            dstream_size: parse_dstream_size(&data[Self::FIXED_SIZE..]),
        })
    }

    /// File-type bits of `mode` (`S_IF*`)
    pub fn kind(&self) -> u16 {
        self.mode & 0o170000
    }

    /// Logical file size: dstream xfield if present, else `uncompressed_size`
    pub fn size(&self) -> u64 {
        self.dstream_size.unwrap_or(self.uncompressed_size)
    }

    pub fn nlink(&self) -> u32 {
        self.nchildren_or_nlink as u32
    }

    /// Write the fixed 92-byte prefix into `out`. Caller appends xfields
    pub fn write_fixed(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < Self::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "inode buffer too short: {} < {}",
                out.len(),
                Self::FIXED_SIZE
            )));
        }
        out[0..8].copy_from_slice(&self.parent_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.private_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.create_time.to_le_bytes());
        out[24..32].copy_from_slice(&self.modify_time.to_le_bytes());
        out[32..40].copy_from_slice(&self.change_time.to_le_bytes());
        out[40..48].copy_from_slice(&self.access_time.to_le_bytes());
        out[48..56].copy_from_slice(&self.internal_flags.to_le_bytes());
        out[56..60].copy_from_slice(&self.nchildren_or_nlink.to_le_bytes());
        out[60..64].copy_from_slice(&self.default_protection_class.to_le_bytes());
        out[64..68].copy_from_slice(&self.write_generation_counter.to_le_bytes());
        out[68..72].copy_from_slice(&self.bsd_flags.to_le_bytes());
        out[72..76].copy_from_slice(&self.uid.to_le_bytes());
        out[76..80].copy_from_slice(&self.gid.to_le_bytes());
        out[80..82].copy_from_slice(&self.mode.to_le_bytes());
        out[82..84].copy_from_slice(&self.pad1.to_le_bytes());
        out[84..92].copy_from_slice(&self.uncompressed_size.to_le_bytes());
        Ok(())
    }

    /// Concatenate the 92-byte fixed prefix and a caller-supplied xfields blob
    pub fn serialize_with_xfields(&self, xfields: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; Self::FIXED_SIZE + xfields.len()];
        self.write_fixed(&mut out[..Self::FIXED_SIZE])?;
        out[Self::FIXED_SIZE..].copy_from_slice(xfields);
        Ok(out)
    }
}

/// Locate the byte range inside the xfields blob that holds the dstream
/// `size` u64 (the first 8 bytes of the dstream xfield's data area). Returns
/// `(start, end)` offsets relative to the start of `blob`, or `None` if the
/// inode has no dstream xfield
fn locate_dstream_size_range(blob: &[u8]) -> Option<(usize, usize)> {
    if blob.len() < 4 {
        return None;
    }
    let num = u16::from_le_bytes([blob[0], blob[1]]) as usize;
    if num == 0 {
        return None;
    }
    let descriptors_off = 4usize;
    let descriptors_end = descriptors_off.checked_add(num.checked_mul(4)?)?;
    if descriptors_end > blob.len() {
        return None;
    }
    let mut data_cursor = descriptors_end;
    for i in 0..num {
        let dest = descriptors_off + i * 4;
        let x_type = blob[dest];
        let x_size = u16::from_le_bytes([blob[dest + 2], blob[dest + 3]]) as usize;
        if x_type == INO_EXT_TYPE_DSTREAM && x_size >= 8 {
            let end = data_cursor.checked_add(8)?;
            if end > blob.len() {
                return None;
            }
            return Some((data_cursor, end));
        }
        let padded = (x_size.checked_add(7)?) & !7;
        data_cursor = data_cursor.checked_add(padded)?;
    }
    None
}

/// Find the `INO_EXT_TYPE_DSTREAM` xfield and return its logical size, or `None`
fn parse_dstream_size(blob: &[u8]) -> Option<u64> {
    let (start, end) = locate_dstream_size_range(blob)?;
    let bytes = blob.get(start..end)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// j_drec_val_t  (directory record)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DrecVal {
    pub file_id: u64,
    pub date_added: i64,
    pub flags: u16,
}

impl DrecVal {
    pub const FIXED_SIZE: usize = 18;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "drec value too short: {} bytes",
                data.len()
            )));
        }
        Ok(Self {
            file_id: rd_u64(data, 0),
            date_added: rd_i64(data, 8),
            flags: rd_u16(data, 16),
        })
    }

    /// `DT_*` constant from the low nibble of `flags`
    pub fn file_type(&self) -> u16 {
        self.flags & 0x000F
    }

    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < Self::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "drec buffer too short: {} < {}",
                out.len(),
                Self::FIXED_SIZE
            )));
        }
        out[0..8].copy_from_slice(&self.file_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.date_added.to_le_bytes());
        out[16..18].copy_from_slice(&self.flags.to_le_bytes());
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::FIXED_SIZE];
        self.write(&mut out).expect("FIXED_SIZE buf fits");
        out
    }
}

// ---------------------------------------------------------------------------
// j_file_extent_val_t
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileExtentVal {
    /// Top byte = flags, low 56 bits = length in bytes
    pub flags_and_length: u64,
    pub phys_block_num: u64,
    pub crypto_id: u64,
}

impl FileExtentVal {
    pub const FIXED_SIZE: usize = 24;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "file extent value too short: {} bytes",
                data.len()
            )));
        }
        Ok(Self {
            flags_and_length: rd_u64(data, 0),
            phys_block_num: rd_u64(data, 8),
            crypto_id: rd_u64(data, 16),
        })
    }

    pub fn length(&self) -> u64 {
        self.flags_and_length & 0x00FF_FFFF_FFFF_FFFF
    }

    pub fn from_length_and_flags(length: u64, flags: u8, phys_block_num: u64, crypto_id: u64) -> Self {
        debug_assert_eq!(length & 0xFF00_0000_0000_0000, 0, "length exceeds 56 bits");
        let flags_and_length = (length & 0x00FF_FFFF_FFFF_FFFF) | ((flags as u64) << 56);
        Self {
            flags_and_length,
            phys_block_num,
            crypto_id,
        }
    }

    pub fn write(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < Self::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "extent buffer too short: {} < {}",
                out.len(),
                Self::FIXED_SIZE
            )));
        }
        out[0..8].copy_from_slice(&self.flags_and_length.to_le_bytes());
        out[8..16].copy_from_slice(&self.phys_block_num.to_le_bytes());
        out[16..24].copy_from_slice(&self.crypto_id.to_le_bytes());
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::FIXED_SIZE];
        self.write(&mut out).expect("FIXED_SIZE buf fits");
        out
    }
}

// ---------------------------------------------------------------------------
// Key decoders
// ---------------------------------------------------------------------------

/// Decode a catalog key into `(obj_id, j_type)`. The on-disk `j_key_t` packs
/// both into a single LE u64: low 60 bits = object id, top 4 bits = type tag
pub fn decode_catalog_key(key: &[u8]) -> Result<(u64, u8)> {
    if key.len() < 8 {
        return Err(ApfsError::BadBTree("catalog key too short".into()));
    }
    let raw = rd_u64(key, 0);
    Ok((raw & 0x0FFF_FFFF_FFFF_FFFF, ((raw >> 60) & 0xF) as u8))
}

/// Convenience alias retained for older callers
pub fn decode_catalog_key_pub(key: &[u8]) -> Result<(u64, u8)> {
    decode_catalog_key(key)
}

/// Extract the file name from a `j_drec_hashed_key_t`. Layout: 8-byte
/// `obj_id_and_type`, 4-byte `name_len_and_hash` (low 10 bits = name length
/// including trailing NUL), then the UTF-8 name
fn decode_drec_name(key: &[u8]) -> Result<String> {
    if key.len() < 12 {
        return Err(ApfsError::BadBTree("drec key too short for name".into()));
    }
    let nlh = rd_u32(key, 8);
    let name_len = (nlh & 0x0000_03FF) as usize;
    let name_end = 12usize.checked_add(name_len).ok_or_else(|| {
        ApfsError::BadBTree("drec name length overflow".into())
    })?;
    if name_end > key.len() {
        return Err(ApfsError::BadBTree(format!(
            "drec name extends past key: end={name_end}, len={}",
            key.len()
        )));
    }
    let bytes = &key[12..name_end];
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..nul]).to_string())
}

/// Compare two `(oid, type)` pairs in APFS sort order
fn cmp_keys(oid_a: u64, type_a: u8, oid_b: u64, type_b: u8) -> Ordering {
    match oid_a.cmp(&oid_b) {
        Ordering::Equal => type_a.cmp(&type_b),
        ord => ord,
    }
}

// ---------------------------------------------------------------------------
// Lookup & scan routines
// ---------------------------------------------------------------------------

/// Look up the `j_inode_val_t` for `oid`
pub fn lookup_inode<R: Read + Seek>(
    reader: &mut R,
    catalog_root: u64,
    omap_root: u64,
    block_size: u32,
    oid: u64,
) -> Result<InodeVal> {
    let cmp = move |key: &[u8]| -> Ordering {
        let (k_oid, k_type) = match decode_catalog_key(key) {
            Ok(t) => t,
            Err(_) => return Ordering::Less,
        };
        cmp_keys(k_oid, k_type, oid, J_TYPE_INODE)
    };
    let val = btree::btree_lookup(
        reader,
        catalog_root,
        block_size,
        0,
        0,
        &cmp,
        Some(omap_root),
    )?
    .ok_or_else(|| ApfsError::NotFound(format!("inode oid {oid}")))?;
    InodeVal::parse(&val)
}

/// Scan the catalog for every `J_TYPE_FILE_EXTENT` whose key oid matches
pub fn lookup_extents<R: Read + Seek>(
    reader: &mut R,
    catalog_root: u64,
    omap_root: u64,
    block_size: u32,
    file_oid: u64,
) -> Result<Vec<FileExtentVal>> {
    let range = move |key: &[u8]| -> Option<bool> {
        let (k_oid, k_type) = match decode_catalog_key(key) {
            Ok(t) => t,
            Err(_) => return Some(false),
        };
        match cmp_keys(k_oid, k_type, file_oid, J_TYPE_FILE_EXTENT) {
            Ordering::Less => Some(false),
            Ordering::Equal => Some(true),
            Ordering::Greater => None,
        }
    };
    let entries = btree::btree_scan(
        reader,
        catalog_root,
        block_size,
        0,
        0,
        &range,
        Some(omap_root),
    )?;
    let mut out = Vec::with_capacity(entries.len());
    for (_k, v) in entries {
        out.push(FileExtentVal::parse(&v)?);
    }
    Ok(out)
}

/// List directory entries under `parent_oid`. The child inode is resolved lazily for size and timestamps
pub fn list_directory<R: Read + Seek>(
    reader: &mut R,
    catalog_root: u64,
    omap_root: u64,
    block_size: u32,
    parent_oid: u64,
) -> Result<Vec<DirEntry>> {
    let range = move |key: &[u8]| -> Option<bool> {
        let (k_oid, k_type) = match decode_catalog_key(key) {
            Ok(t) => t,
            Err(_) => return Some(false),
        };
        match cmp_keys(k_oid, k_type, parent_oid, J_TYPE_DIR_REC) {
            Ordering::Less => Some(false),
            Ordering::Equal => Some(true),
            Ordering::Greater => None,
        }
    };
    let raw = btree::btree_scan(
        reader,
        catalog_root,
        block_size,
        0,
        0,
        &range,
        Some(omap_root),
    )?;

    let mut out = Vec::with_capacity(raw.len());
    for (key, val) in raw {
        let Ok(name) = decode_drec_name(&key) else { continue };
        let Ok(drec) = DrecVal::parse(&val) else { continue };
        let kind = match drec.file_type() {
            DT_DIR => EntryKind::Directory,
            DT_LNK => EntryKind::Symlink,
            _ => EntryKind::File,
        };
        let (size, create_time, modify_time) =
            match lookup_inode(reader, catalog_root, omap_root, block_size, drec.file_id) {
                Ok(i) => (i.size(), i.create_time, i.modify_time),
                Err(_) => (0, 0, 0),
            };
        out.push(DirEntry {
            name,
            oid: drec.file_id,
            kind,
            size,
            create_time,
            modify_time,
        });
    }
    Ok(out)
}

/// Walk a slash-separated path from the root and return `(oid, inode)`
pub fn resolve_path<R: Read + Seek>(
    reader: &mut R,
    catalog_root: u64,
    omap_root: u64,
    block_size: u32,
    path: &str,
) -> Result<(u64, InodeVal)> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        let inode = lookup_inode(reader, catalog_root, omap_root, block_size, ROOT_DIR_RECORD)?;
        return Ok((ROOT_DIR_RECORD, inode));
    }
    let comps: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    let mut parent = ROOT_DIR_RECORD;
    for (i, comp) in comps.iter().enumerate() {
        let drec = lookup_drec(reader, catalog_root, omap_root, block_size, parent, comp)?;
        if i == comps.len() - 1 {
            let inode = lookup_inode(reader, catalog_root, omap_root, block_size, drec.file_id)?;
            return Ok((drec.file_id, inode));
        }
        if drec.file_type() != DT_DIR {
            return Err(ApfsError::NotADirectory(comps[..=i].join("/")));
        }
        parent = drec.file_id;
    }
    unreachable!()
}

fn lookup_drec<R: Read + Seek>(
    reader: &mut R,
    catalog_root: u64,
    omap_root: u64,
    block_size: u32,
    parent_oid: u64,
    name: &str,
) -> Result<DrecVal> {
    let range = move |key: &[u8]| -> Option<bool> {
        let (k_oid, k_type) = match decode_catalog_key(key) {
            Ok(t) => t,
            Err(_) => return Some(false),
        };
        match cmp_keys(k_oid, k_type, parent_oid, J_TYPE_DIR_REC) {
            Ordering::Less => Some(false),
            Ordering::Equal => Some(true),
            Ordering::Greater => None,
        }
    };
    let entries = btree::btree_scan(
        reader,
        catalog_root,
        block_size,
        0,
        0,
        &range,
        Some(omap_root),
    )?;
    for (key, val) in entries {
        if let Ok(n) = decode_drec_name(&key)
            && n == name
        {
            return DrecVal::parse(&val);
        }
    }
    Err(ApfsError::NotFound(name.to_string()))
}

// ---------------------------------------------------------------------------
// In-place inode mutation primitive
// ---------------------------------------------------------------------------

/// Overwrite timestamp fields in the `J_TYPE_INODE` record for `oid` inside `node`
/// `None` arguments are left unchanged; xfields are preserved. Returns the entry index
pub fn set_inode_times_in_node(
    node: &mut BTreeNode,
    oid: u64,
    create_time: Option<i64>,
    modify_time: Option<i64>,
    change_time: Option<i64>,
    access_time: Option<i64>,
) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "set_inode_times_in_node: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = decode_catalog_key(key)?;
        if k_type != J_TYPE_INODE || k_oid != oid {
            continue;
        }
        let val = node.value_at(i, 0)?;
        if val.len() < InodeVal::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "inode value truncated: {} bytes",
                val.len()
            )));
        }
        let mut inode = InodeVal::parse(val)?;
        if let Some(t) = create_time {
            inode.create_time = t;
        }
        if let Some(t) = modify_time {
            inode.modify_time = t;
        }
        if let Some(t) = change_time {
            inode.change_time = t;
        }
        if let Some(t) = access_time {
            inode.access_time = t;
        }
        let xfields = val[InodeVal::FIXED_SIZE..].to_vec();
        let new_val = inode.serialize_with_xfields(&xfields)?;
        node.replace_value(i, &new_val, 0)?;
        return Ok(i);
    }
    Err(ApfsError::NotFound(format!("inode {oid} not in node")))
}

/// Splice a new logical size into the dstream xfield of the inode for `oid`
/// inside `node`. Same-size mutation: the dstream blob is fixed-format so the
/// containing value's overall length never changes. Returns the entry index
///
/// This intentionally does NOT touch `alloced_size` or release any extents
/// Callers that genuinely shrink a file under loopback semantics accept that
/// allocated blocks past the new logical EOF will leak until a future
/// extent-aware truncation path lands
pub fn set_inode_dstream_size_in_node(
    node: &mut BTreeNode,
    oid: u64,
    new_size: u64,
) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "set_inode_dstream_size_in_node: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = decode_catalog_key(key)?;
        if k_type != J_TYPE_INODE || k_oid != oid {
            continue;
        }
        let val = node.value_at(i, 0)?;
        if val.len() < InodeVal::FIXED_SIZE {
            return Err(ApfsError::BadCatalog(format!(
                "inode value truncated: {} bytes",
                val.len()
            )));
        }
        let xfields_off = InodeVal::FIXED_SIZE;
        let xfields = &val[xfields_off..];
        let (rel_start, rel_end) = locate_dstream_size_range(xfields).ok_or_else(|| {
            ApfsError::BadCatalog(format!("inode {oid} has no dstream xfield"))
        })?;
        let mut new_val = val.to_vec();
        new_val[xfields_off + rel_start..xfields_off + rel_end]
            .copy_from_slice(&new_size.to_le_bytes());
        node.replace_value(i, &new_val, 0)?;
        return Ok(i);
    }
    Err(ApfsError::NotFound(format!("inode {oid} not in node")))
}

// ---------------------------------------------------------------------------
// In-leaf delete primitives (loopback semantics; no node merge / split)
// ---------------------------------------------------------------------------

/// Find the entry index in `node` matching `(oid, j_type)`. Drec records
/// share a single (oid, type) prefix but disambiguate by name; pass
/// `Some(name)` to match the drec carrying that exact filename. Returns
/// `None` if no entry matches
pub fn find_record_in_node(
    node: &BTreeNode,
    oid: u64,
    j_type: u8,
    drec_name: Option<&str>,
) -> Result<Option<usize>> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "find_record_in_node: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = match decode_catalog_key(key) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if k_oid != oid || k_type != j_type {
            continue;
        }
        if let Some(name) = drec_name {
            let Ok(decoded) = decode_drec_name(key) else { continue };
            if decoded != name {
                continue;
            }
        }
        return Ok(Some(i));
    }
    Ok(None)
}

/// Delete every entry in `node` whose key matches `(oid, j_type)`. Returns
/// the count removed. Used for sweeping all `J_TYPE_FILE_EXTENT` records
/// of a file out of one leaf in a single pass
pub fn delete_records_in_node(
    node: &mut BTreeNode,
    oid: u64,
    j_type: u8,
) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "delete_records_in_node: target is not a leaf".into(),
        ));
    }
    let mut removed = 0;
    let mut i = 0;
    while i < node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = match decode_catalog_key(key) {
            Ok(t) => t,
            Err(_) => {
                i += 1;
                continue;
            }
        };
        if k_oid == oid && k_type == j_type {
            node.delete_leaf_var(i)?;
            removed += 1;
            // don't advance `i`; the next entry shifts into this slot
        } else {
            i += 1;
        }
    }
    Ok(removed)
}

/// Decrement `nchildren_or_nlink` of the inode for `oid` inside `node`
/// Caller is responsible for picking the parent dir's inode (where this
/// field acts as nchildren); applying it to a regular file's inode would
/// decrement `nlink` instead. Returns the entry index. Errors if the
/// counter is already zero
pub fn dec_inode_counter_in_node(node: &mut BTreeNode, oid: u64) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "dec_inode_counter_in_node: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = decode_catalog_key(key)?;
        if k_type != J_TYPE_INODE || k_oid != oid {
            continue;
        }
        let val = node.value_at(i, 0)?;
        let mut inode = InodeVal::parse(val)?;
        if inode.nchildren_or_nlink <= 0 {
            return Err(ApfsError::BadCatalog(format!(
                "inode {oid}: counter already {}",
                inode.nchildren_or_nlink
            )));
        }
        inode.nchildren_or_nlink -= 1;
        let xfields = val[InodeVal::FIXED_SIZE..].to_vec();
        let new_val = inode.serialize_with_xfields(&xfields)?;
        node.replace_value(i, &new_val, 0)?;
        return Ok(i);
    }
    Err(ApfsError::NotFound(format!("inode {oid} not in node")))
}

// ---------------------------------------------------------------------------
// In-leaf insert primitives
// ---------------------------------------------------------------------------

/// Locate the insertion index for `new_key` inside `node`'s sorted TOC
/// The first entry whose key is greater than `new_key` is the insertion
/// point. Errors if a duplicate key already exists
pub fn find_insert_index(node: &BTreeNode, new_key: &[u8]) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "find_insert_index: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let existing = node.key_at(i, 0)?;
        match cmp_catalog_keys(existing, new_key) {
            Ordering::Less => continue,
            Ordering::Equal => {
                return Err(ApfsError::Internal(format!(
                    "find_insert_index: duplicate key at idx {i}"
                )));
            }
            Ordering::Greater => return Ok(i),
        }
    }
    Ok(node.nkeys())
}

/// Build a hashed drec key: 8-byte obj_id_and_type, 4-byte name_len_and_hash,
/// UTF-8 name, trailing NUL byte
///
/// `name_len_with_nul = name.len() + 1` must fit in 10 bits (max 1023)
pub fn encode_drec_hashed_key(parent_oid: u64, name: &str, hash22: u32) -> Result<Vec<u8>> {
    let name_len_with_nul = name.len() + 1;
    if name_len_with_nul > 0x3FF {
        return Err(ApfsError::BadCatalog(format!(
            "drec name length {name_len_with_nul} exceeds 1023"
        )));
    }
    let nlh = (name_len_with_nul as u32 & 0x3FF) | ((hash22 & 0x003F_FFFF) << 10);
    let mut out = Vec::with_capacity(12 + name_len_with_nul);
    out.extend_from_slice(&encode_obj_id_and_type(parent_oid, J_TYPE_DIR_REC));
    out.extend_from_slice(&nlh.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    Ok(out)
}

/// Insert a directory record under `parent_oid` with the given hashed name
/// The catalog tree must have the HASHED flag set (which is the default for
/// modern APFS volumes)
#[allow(clippy::too_many_arguments)]
pub fn insert_drec_record(
    node: &mut BTreeNode,
    parent_oid: u64,
    name: &str,
    hash22: u32,
    file_id: u64,
    date_added: i64,
    file_type: u16,
) -> Result<usize> {
    let key = encode_drec_hashed_key(parent_oid, name, hash22)?;
    let val = DrecVal {
        file_id,
        date_added,
        flags: file_type,
    }
    .to_bytes();
    let idx = find_insert_index(node, &key)?;
    node.insert_leaf_var(idx, &key, &val)?;
    Ok(idx)
}

/// Insert a `J_TYPE_INODE` record. Caller supplies the encoded inode value
/// (fixed prefix + xfields); see [`InodeVal::serialize_with_xfields`]
pub fn insert_inode_record(node: &mut BTreeNode, oid: u64, value: &[u8]) -> Result<usize> {
    let mut key = Vec::with_capacity(8);
    key.extend_from_slice(&encode_obj_id_and_type(oid, J_TYPE_INODE));
    let idx = find_insert_index(node, &key)?;
    node.insert_leaf_var(idx, &key, value)?;
    Ok(idx)
}

/// Insert a `J_TYPE_DSTREAM_ID` record. The value is a 4-byte refcnt
pub fn insert_dstream_id_record(node: &mut BTreeNode, oid: u64, refcnt: u32) -> Result<usize> {
    let mut key = Vec::with_capacity(8);
    key.extend_from_slice(&encode_obj_id_and_type(oid, J_TYPE_DSTREAM_ID));
    let val = refcnt.to_le_bytes();
    let idx = find_insert_index(node, &key)?;
    node.insert_leaf_var(idx, &key, &val)?;
    Ok(idx)
}

/// Insert a `J_TYPE_FILE_EXTENT` record. Key is 8-byte obj_id_and_type
/// followed by 8-byte logical addr; value is a 24-byte `j_file_extent_val_t`
pub fn insert_file_extent_record(
    node: &mut BTreeNode,
    oid: u64,
    logical_addr: u64,
    length: u64,
    phys_block: u64,
) -> Result<usize> {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&encode_obj_id_and_type(oid, J_TYPE_FILE_EXTENT));
    key.extend_from_slice(&logical_addr.to_le_bytes());
    let val = FileExtentVal::from_length_and_flags(length, 0, phys_block, 0).to_bytes();
    let idx = find_insert_index(node, &key)?;
    node.insert_leaf_var(idx, &key, &val)?;
    Ok(idx)
}

/// Increment `nchildren_or_nlink` of the inode for `oid` inside `node`
/// Used when a new directory entry is inserted (parent's nchildren) or
/// when a hardlink is added (file's nlink). Returns the entry index
pub fn inc_inode_counter_in_node(node: &mut BTreeNode, oid: u64) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "inc_inode_counter_in_node: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = decode_catalog_key(key)?;
        if k_type != J_TYPE_INODE || k_oid != oid {
            continue;
        }
        let val = node.value_at(i, 0)?;
        let mut inode = InodeVal::parse(val)?;
        inode.nchildren_or_nlink = inode.nchildren_or_nlink.saturating_add(1);
        let xfields = val[InodeVal::FIXED_SIZE..].to_vec();
        let new_val = inode.serialize_with_xfields(&xfields)?;
        node.replace_value(i, &new_val, 0)?;
        return Ok(i);
    }
    Err(ApfsError::NotFound(format!("inode {oid} not in node")))
}

/// Build a serialised inode value with an optional `j_dstream_t` xfield
/// holding `dstream_size`. Pass `None` to omit the xfield (used for
/// directories and zero-length files)
pub fn build_inode_value(
    template: &InodeVal,
    dstream: Option<JDstream>,
) -> Result<Vec<u8>> {
    let xfields = match dstream {
        None => Vec::new(),
        Some(ds) => build_dstream_xfields(&ds),
    };
    template.serialize_with_xfields(&xfields)
}

/// Subset of `j_dstream_t` we serialise for newly-created files
#[derive(Debug, Clone, Copy)]
pub struct JDstream {
    pub size: u64,
    pub alloced_size: u64,
    pub default_crypto_id: u64,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
}

fn build_dstream_xfields(ds: &JDstream) -> Vec<u8> {
    // xf_blob_t: u16 num_exts, u16 used_data, then descriptors then data
    // One descriptor: x_type=INO_EXT_TYPE_DSTREAM, x_flags=0, x_size=40
    let payload: Vec<u8> = {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(&ds.size.to_le_bytes());
        p.extend_from_slice(&ds.alloced_size.to_le_bytes());
        p.extend_from_slice(&ds.default_crypto_id.to_le_bytes());
        p.extend_from_slice(&ds.total_bytes_written.to_le_bytes());
        p.extend_from_slice(&ds.total_bytes_read.to_le_bytes());
        p
    };
    let payload_padded = (payload.len() + 7) & !7;
    let used_data = payload_padded; // descriptors do not count toward used_data
    let mut out = Vec::with_capacity(4 + 4 + payload_padded);
    out.extend_from_slice(&1u16.to_le_bytes()); // num_exts
    out.extend_from_slice(&(used_data as u16).to_le_bytes()); // used_data
    out.push(INO_EXT_TYPE_DSTREAM); // x_type
    out.push(0u8); // x_flags
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // x_size
    out.extend_from_slice(&payload);
    while out.len() < 4 + 4 + payload_padded {
        out.push(0);
    }
    out
}

/// Splice a fresh dstream `size` and `alloced_size` into the inode for
/// `oid` inside `node`. Same-size mutation: if no dstream xfield exists yet
/// this errors; use `replace_inode_value_in_node` for cases that need to
/// add or remove the xfield (the value length changes in those cases)
pub fn set_inode_dstream_size_and_alloc_in_node(
    node: &mut BTreeNode,
    oid: u64,
    new_size: u64,
    new_alloced_size: u64,
) -> Result<usize> {
    if !node.is_leaf() {
        return Err(ApfsError::BadBTree(
            "set_inode_dstream_size_and_alloc_in_node: target is not a leaf".into(),
        ));
    }
    for i in 0..node.nkeys() {
        let key = node.key_at(i, 0)?;
        let (k_oid, k_type) = decode_catalog_key(key)?;
        if k_type != J_TYPE_INODE || k_oid != oid {
            continue;
        }
        let val = node.value_at(i, 0)?;
        let xfields_off = InodeVal::FIXED_SIZE;
        let xfields = &val[xfields_off..];
        let (rel_start, rel_end) = locate_dstream_size_range(xfields).ok_or_else(|| {
            ApfsError::BadCatalog(format!("inode {oid} has no dstream xfield"))
        })?;
        let mut new_val = val.to_vec();
        new_val[xfields_off + rel_start..xfields_off + rel_end]
            .copy_from_slice(&new_size.to_le_bytes());
        // alloced_size sits immediately after `size` in the dstream payload
        let alloced_off = xfields_off + rel_end;
        if alloced_off + 8 <= new_val.len() {
            new_val[alloced_off..alloced_off + 8]
                .copy_from_slice(&new_alloced_size.to_le_bytes());
        }
        node.replace_value(i, &new_val, 0)?;
        return Ok(i);
    }
    Err(ApfsError::NotFound(format!("inode {oid} not in node")))
}

/// Replace the inode record for `oid` in `node` with a freshly-encoded value
/// The new value's length may differ from the old one. Implementation detail:
/// we delete the existing entry then re-insert at the same position via the
/// variable-KV insert path. Returns the entry index
pub fn replace_inode_value_in_node(
    node: &mut BTreeNode,
    oid: u64,
    new_value: &[u8],
) -> Result<usize> {
    let idx = find_record_in_node(node, oid, J_TYPE_INODE, None)?
        .ok_or_else(|| ApfsError::NotFound(format!("inode {oid} not in node")))?;
    node.delete_leaf_var(idx)?;
    let mut key = Vec::with_capacity(8);
    key.extend_from_slice(&encode_obj_id_and_type(oid, J_TYPE_INODE));
    node.insert_leaf_var(idx, &key, new_value)?;
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drec_val_roundtrip() {
        let d = DrecVal {
            file_id: 0xDEADBEEF,
            date_added: -123456,
            flags: DT_REG,
        };
        let parsed = DrecVal::parse(&d.to_bytes()).unwrap();
        assert_eq!(parsed.file_id, d.file_id);
        assert_eq!(parsed.flags, d.flags);
    }

    #[test]
    fn file_extent_roundtrip_preserves_flags_and_length() {
        let e = FileExtentVal::from_length_and_flags(0x4000, 0x12, 999, 7);
        let parsed = FileExtentVal::parse(&e.to_bytes()).unwrap();
        assert_eq!(parsed.length(), 0x4000);
        assert_eq!(parsed.phys_block_num, 999);
        assert_eq!(parsed.crypto_id, 7);
        assert_eq!(parsed.flags_and_length, e.flags_and_length);
    }

    #[test]
    fn inode_roundtrip_no_xfields() {
        let i = InodeVal {
            parent_id: 1,
            private_id: 16,
            create_time: 1_000,
            modify_time: 2_000,
            change_time: 3_000,
            access_time: 4_000,
            internal_flags: 0,
            nchildren_or_nlink: 1,
            default_protection_class: 0,
            write_generation_counter: 1,
            bsd_flags: 0,
            uid: 501,
            gid: 20,
            mode: INODE_FILE_TYPE | 0o644,
            pad1: 0,
            uncompressed_size: 4096,
            dstream_size: None,
        };
        let bytes = i.serialize_with_xfields(&[]).unwrap();
        let parsed = InodeVal::parse(&bytes).unwrap();
        assert_eq!(parsed.uid, i.uid);
        assert_eq!(parsed.mode, i.mode);
        assert_eq!(parsed.uncompressed_size, i.uncompressed_size);
    }

    #[test]
    fn dstream_xfield_is_recognised() {
        let mut xf = Vec::new();
        xf.extend_from_slice(&1u16.to_le_bytes()); // num_exts
        xf.extend_from_slice(&8u16.to_le_bytes()); // used_data
        xf.push(INO_EXT_TYPE_DSTREAM);
        xf.push(0u8);
        xf.extend_from_slice(&8u16.to_le_bytes());
        xf.extend_from_slice(&0x1234_5678u64.to_le_bytes());

        let i = InodeVal {
            parent_id: 2,
            private_id: 100,
            create_time: 0,
            modify_time: 0,
            change_time: 0,
            access_time: 0,
            internal_flags: 0,
            nchildren_or_nlink: 1,
            default_protection_class: 0,
            write_generation_counter: 0,
            bsd_flags: 0,
            uid: 0,
            gid: 0,
            mode: INODE_FILE_TYPE | 0o600,
            pad1: 0,
            uncompressed_size: 0,
            dstream_size: None,
        };
        let bytes = i.serialize_with_xfields(&xf).unwrap();
        let parsed = InodeVal::parse(&bytes).unwrap();
        assert_eq!(parsed.dstream_size, Some(0x1234_5678));
        assert_eq!(parsed.size(), 0x1234_5678);
    }

    #[test]
    fn decode_catalog_key_splits_oid_and_type() {
        // type=J_TYPE_INODE (3) in top 4 bits, oid=0x123 in low bits
        let raw: u64 = 0x123 | ((J_TYPE_INODE as u64) << 60);
        let bytes = raw.to_le_bytes();
        let (oid, t) = decode_catalog_key(&bytes).unwrap();
        assert_eq!(oid, 0x123);
        assert_eq!(t, J_TYPE_INODE);
    }
}
