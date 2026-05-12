//! Object header (`obj_phys_t`) plus the small set of object-type constants we
//! actually consume. APFS spec uses a 32-byte preamble at the start of every
//! managed block: 8-byte Fletcher checksum, 64-bit OID, 64-bit XID, then
//! `(type, subtype)` 32-bit pairs
use crate::apfs::error::{ApfsError, Result};
use crate::apfs::fletcher;
use std::io::{Read, Seek, SeekFrom};

pub const OBJECT_HEADER_SIZE: usize = 32;

// `o_type` low 16 bits = type, high 16 bits = flag bits. We ignore most flags;
// only the storage class matters for routing reads
pub const TYPE_MASK: u32 = 0x0000_FFFF;
pub const FLAG_MASK: u32 = 0xFFFF_0000;

// Object types we recognise. Numbers are from APFS Reference (Apple, 2020)
pub const OBJECT_TYPE_NX_SUPERBLOCK: u16 = 0x01;
pub const OBJECT_TYPE_BTREE: u16 = 0x02;
pub const OBJECT_TYPE_BTREE_NODE: u16 = 0x03;
pub const OBJECT_TYPE_SPACEMAN: u16 = 0x05;
pub const OBJECT_TYPE_SPACEMAN_CAB: u16 = 0x06;
pub const OBJECT_TYPE_SPACEMAN_CIB: u16 = 0x07;
pub const OBJECT_TYPE_SPACEMAN_BITMAP: u16 = 0x08;
pub const OBJECT_TYPE_OMAP: u16 = 0x0B;
pub const OBJECT_TYPE_CHECKPOINT_MAP: u16 = 0x0C;
pub const OBJECT_TYPE_FS: u16 = 0x0D;
pub const OBJECT_TYPE_FSTREE: u16 = 0x0E;
pub const OBJECT_TYPE_INVALID: u16 = 0x00;

/// Parsed 32-byte object header. All fields are plain integers; no borrow into the source block
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectHeader {
    pub checksum: [u8; 8],
    pub oid: u64,
    pub xid: u64,
    pub raw_type: u32,
    pub subtype: u32,
}

impl ObjectHeader {
    pub const SIZE: usize = OBJECT_HEADER_SIZE;

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(ApfsError::Truncated {
                need: Self::SIZE,
                have: bytes.len(),
            });
        }
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&bytes[..8]);
        Ok(Self {
            checksum,
            oid: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            xid: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            raw_type: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            subtype: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        })
    }

    pub fn write_into(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(ApfsError::Truncated {
                need: Self::SIZE,
                have: buf.len(),
            });
        }
        buf[..8].copy_from_slice(&self.checksum);
        buf[8..16].copy_from_slice(&self.oid.to_le_bytes());
        buf[16..24].copy_from_slice(&self.xid.to_le_bytes());
        buf[24..28].copy_from_slice(&self.raw_type.to_le_bytes());
        buf[28..32].copy_from_slice(&self.subtype.to_le_bytes());
        Ok(())
    }

    pub fn object_type(&self) -> u16 {
        (self.raw_type & TYPE_MASK) as u16
    }

    pub fn flags(&self) -> u16 {
        ((self.raw_type & FLAG_MASK) >> 16) as u16
    }

    pub fn expect_type(&self, expected: u16) -> Result<()> {
        if self.object_type() == expected {
            Ok(())
        } else {
            Err(ApfsError::BadObjectType {
                expected,
                actual: self.object_type(),
            })
        }
    }
}

/// Read one block (`block_size` bytes) at physical address `paddr` from
/// `reader`. The Fletcher-64 checksum is **not** verified; many ephemeral
/// objects (spaceman, in-memory checkpoint state) carry stale checksums
/// until they are next written, so unconditional verification is wrong
/// Callers that need a checksum guarantee (e.g. structural validators) must
/// use [`read_block_verified`]
pub fn read_block<R: Read + Seek>(reader: &mut R, paddr: u64, block_size: u32) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; block_size as usize];
    reader.seek(SeekFrom::Start(paddr * block_size as u64))?;
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a block AND verify its Fletcher-64 checksum
pub fn read_block_verified<R: Read + Seek>(
    reader: &mut R,
    paddr: u64,
    block_size: u32,
) -> Result<Vec<u8>> {
    let buf = read_block(reader, paddr, block_size)?;
    if !fletcher::verify_object(&buf) {
        return Err(ApfsError::BadChecksum);
    }
    Ok(buf)
}

/// Alias kept for backward-compatibility with checkpoint-ring scanners; same
/// behaviour as [`read_block`] (no checksum check)
pub fn read_block_unchecked<R: Read + Seek>(
    reader: &mut R,
    paddr: u64,
    block_size: u32,
) -> Result<Vec<u8>> {
    read_block(reader, paddr, block_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_block(block_size: usize, oid: u64, xid: u64, ty: u16) -> Vec<u8> {
        let mut block = vec![0u8; block_size];
        let header = ObjectHeader {
            checksum: [0u8; 8],
            oid,
            xid,
            raw_type: ty as u32,
            subtype: 0,
        };
        header.write_into(&mut block[..32]).unwrap();
        fletcher::refresh_object_checksum(&mut block).unwrap();
        block
    }

    #[test]
    fn parse_writeback_roundtrip() {
        let blk = synth_block(512, 42, 7, OBJECT_TYPE_BTREE_NODE);
        let h = ObjectHeader::parse(&blk).unwrap();
        assert_eq!(h.oid, 42);
        assert_eq!(h.xid, 7);
        assert_eq!(h.object_type(), OBJECT_TYPE_BTREE_NODE);

        let mut copy = vec![0u8; 32];
        h.write_into(&mut copy).unwrap();
        assert_eq!(&copy[..32], &blk[..32]);
    }

    #[test]
    fn flags_split_correctly() {
        let h = ObjectHeader {
            checksum: [0; 8],
            oid: 1,
            xid: 1,
            raw_type: 0xABCD_0042,
            subtype: 0,
        };
        assert_eq!(h.object_type(), 0x0042);
        assert_eq!(h.flags(), 0xABCD);
    }

    #[test]
    fn expect_type_errors_correctly() {
        let h = ObjectHeader {
            checksum: [0; 8],
            oid: 0,
            xid: 0,
            raw_type: OBJECT_TYPE_OMAP as u32,
            subtype: 0,
        };
        assert!(h.expect_type(OBJECT_TYPE_OMAP).is_ok());
        assert!(h.expect_type(OBJECT_TYPE_BTREE).is_err());
    }

    #[test]
    fn truncated_buffer_rejected() {
        assert!(ObjectHeader::parse(&[0u8; 16]).is_err());
    }
}
