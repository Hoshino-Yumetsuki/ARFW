//! APFS Fletcher-64 checksum
//!
//! APFS variant: stream of little-endian 32-bit words; sums kept modulo
//! `2^32 - 1`. The 64-bit "checksum" stored in `obj_phys.o_cksum` is two
//! 32-bit complement values laid out so that re-running the same algorithm
//! over the entire block (checksum field included) yields zero; that is
//! how [`verify_object`] recognises an intact block
const MOD: u64 = (1u64 << 32) - 1;

fn fold(data: &[u8]) -> (u64, u64) {
    let mut sum1 = 0u64;
    let mut sum2 = 0u64;
    let mut iter = data.chunks_exact(4);
    for chunk in iter.by_ref() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
        sum1 = (sum1 + word) % MOD;
        sum2 = (sum1 + sum2) % MOD;
    }
    // APFS blocks are always a multiple of 4 bytes; trailing tail would be a bug
    debug_assert!(
        iter.remainder().is_empty(),
        "fletcher payload must be 4-byte aligned"
    );
    (sum1, sum2)
}

/// Compute the 8-byte Fletcher-64 checksum field for `payload` (everything in
/// the block *except* the leading 8 checksum bytes)
pub fn fletcher64(payload: &[u8]) -> u64 {
    let (s1, s2) = fold(payload);
    let low = MOD - ((s1 + s2) % MOD);
    let high = MOD - ((s1 + low) % MOD);
    (high << 32) | low
}

/// Returns `true` when `block`'s leading 8 bytes match the checksum implied by
/// the rest of the block
pub fn verify_object(block: &[u8]) -> bool {
    if block.len() < 8 || block.len() % 4 != 0 {
        return false;
    }
    let stored = u64::from_le_bytes(block[..8].try_into().unwrap());
    fletcher64(&block[8..]) == stored
}

/// Recompute and write the checksum into `block[..8]`
pub fn refresh_object_checksum(block: &mut [u8]) -> crate::apfs::Result<()> {
    if block.len() < 8 || block.len() % 4 != 0 {
        return Err(crate::apfs::ApfsError::Internal(format!(
            "fletcher: block size {} is invalid (need 4-byte aligned, >=8)",
            block.len()
        )));
    }
    let cksum = fletcher64(&block[8..]).to_le_bytes();
    block[..8].copy_from_slice(&cksum);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_then_verify_roundtrip() {
        let mut block = vec![0u8; 4096];
        // Plant some non-zero payload
        for (i, b) in block[8..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31);
        }
        refresh_object_checksum(&mut block).unwrap();
        assert!(verify_object(&block));
    }

    #[test]
    fn corruption_is_detected() {
        let mut block = vec![0u8; 4096];
        refresh_object_checksum(&mut block).unwrap();
        block[100] ^= 1;
        assert!(!verify_object(&block));
    }

    #[test]
    fn empty_block_is_valid_after_refresh() {
        let mut block = vec![0u8; 512];
        refresh_object_checksum(&mut block).unwrap();
        assert!(verify_object(&block));
    }

    #[test]
    fn rejects_misaligned_block() {
        let mut buf = vec![0u8; 13];
        assert!(refresh_object_checksum(&mut buf).is_err());
    }

    #[test]
    fn fletcher_is_deterministic() {
        let payload = b"\x00\x00\x00\x00abcdEFGH-_-_!?!?";
        assert_eq!(fletcher64(payload), fletcher64(payload));
    }
}
