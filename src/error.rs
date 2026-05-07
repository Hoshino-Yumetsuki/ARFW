use std::io;
use windows::core::Error as WindowsError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Windows API error: {0}")]
    Windows(#[from] WindowsError),

    #[error("APFS error: {0}")]
    Apfs(String),

    #[error("WinFsp error: {0}")]
    WinFsp(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// Convert NTSTATUS to io::Error
pub fn ntstatus_to_io_error(status: i32) -> io::Error {
    use std::io::ErrorKind;
    match status as u32 {
        0xC0000034 => io::Error::new(ErrorKind::NotFound, "Object name not found"),
        0xC000003A => io::Error::new(ErrorKind::NotFound, "Path not found"),
        0xC0000022 => io::Error::new(ErrorKind::PermissionDenied, "Access denied"),
        0xC0000043 => io::Error::new(ErrorKind::InvalidInput, "Sharing violation"),
        _ => io::Error::new(ErrorKind::Other, format!("NTSTATUS: 0x{:08X}", status)),
    }
}
