//! CRC32C (Castagnoli) and APFS filename hashing
//!
//! APFS hashed catalogs key directory records by `crc32c` of the file name
//! encoded as UTF-32LE with a trailing NUL. For case-insensitive volumes
//! the name is folded to lowercase first (Apple uses a complex Unicode
//! table; we implement the ASCII subset only). NFD normalisation is a
//! no-op for ASCII names so we skip it
use crate::apfs::error::{ApfsError, Result};

const POLY_CASTAGNOLI_REV: u32 = 0x82F63B78;

/// Pre-computed CRC32C lookup table built lazily on first use
fn table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ POLY_CASTAGNOLI_REV
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    })
}

/// Update an existing CRC with `bytes`
pub fn crc32c_update(seed: u32, bytes: &[u8]) -> u32 {
    let t = table();
    let mut c = !seed;
    for &b in bytes {
        c = (c >> 8) ^ t[((c ^ b as u32) & 0xFF) as usize];
    }
    !c
}

/// One-shot CRC32C of `bytes` with the standard `0` seed
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c_update(0, bytes)
}

/// Compute the APFS hashed-drec name hash. The 22-bit value goes into the
/// top of the `name_len_and_hash` key field.
///
/// `case_insensitive`: when true, fold ASCII letters to lowercase before
/// hashing. Apple's full Unicode case-folding table is not implemented;
/// names with non-ASCII bytes return `Unsupported`
pub fn drec_name_hash(name: &str, case_insensitive: bool) -> Result<u32> {
    if !name.is_ascii() {
        return Err(ApfsError::Unsupported(format!(
            "non-ASCII filename '{name}': APFS Unicode case-fold/NFD not implemented"
        )));
    }
    // UTF-32LE encoding of name + NUL terminator. ASCII chars map 1:1 to
    // a u32 codepoint. The hash domain is the *bytes* of that encoding
    let mut encoded: Vec<u8> = Vec::with_capacity(4 * (name.len() + 1));
    for ch in name.chars() {
        let cp = if case_insensitive {
            ch.to_ascii_lowercase() as u32
        } else {
            ch as u32
        };
        encoded.extend_from_slice(&cp.to_le_bytes());
    }
    encoded.extend_from_slice(&0u32.to_le_bytes());
    Ok(crc32c(&encoded) & 0x003F_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        // RFC 3720 Castagnoli reference: crc32c("123456789") = 0xE3069283
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc32c_empty_input_is_zero() {
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn drec_hash_is_deterministic_and_22bit() {
        let h = drec_name_hash("hello.txt", false).unwrap();
        assert_eq!(h, drec_name_hash("hello.txt", false).unwrap());
        assert!(h <= 0x003F_FFFF);
    }

    #[test]
    fn drec_hash_case_insensitive_folds_ascii() {
        let a = drec_name_hash("Hello.Txt", true).unwrap();
        let b = drec_name_hash("hello.txt", true).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn drec_hash_rejects_non_ascii() {
        assert!(drec_name_hash("héllo.txt", false).is_err());
    }
}
