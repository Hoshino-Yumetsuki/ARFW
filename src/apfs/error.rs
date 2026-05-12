//! Error types for APFS parsing and I/O
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApfsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not an APFS container (magic {0:#010x})")]
    BadContainerMagic(u32),

    #[error("not an APFS volume superblock (magic {0:#010x})")]
    BadVolumeMagic(u32),

    #[error("Fletcher-64 checksum mismatch in object")]
    BadChecksum,

    #[error("object header type mismatch: expected {expected:#06x}, got {actual:#06x}")]
    BadObjectType { expected: u16, actual: u16 },

    #[error("buffer too small: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },

    #[error("malformed b-tree node: {0}")]
    BadBTree(String),

    #[error("malformed catalog record: {0}")]
    BadCatalog(String),

    #[error("file not found: {0}")]
    NotFound(String),

    #[error("unsupported volume layout: {0}")]
    Unsupported(String),

    #[error("no usable volume in container")]
    NoVolume,

    #[error("not a directory: {0}")]
    NotADirectory(String),

    #[error("internal invariant broken: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ApfsError>;
