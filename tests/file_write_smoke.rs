//! End-to-end smoke for `ApfsVolume::write_at`: overwrite bytes inside an
//! existing file and verify they survive a re-mount and structural verify
mod common;

use arfw::apfs::{ApfsVolume, EntryKind, verify::verify_image};

#[test]
fn write_at_overwrites_existing_bytes_in_place() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("write_at_overwrites_existing_bytes_in_place");
            return;
        }
    };

    // Pick the largest non-empty regular file so we can write at least 16
    // bytes well clear of any header on the file
    let target_path = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open volume (ro view)");
        let walk = vol.walk().expect("walk");
        walk.into_iter()
            .filter(|e| e.entry.kind == EntryKind::File && e.entry.size >= 32)
            .max_by_key(|e| e.entry.size)
            .expect("fixture has a regular file >= 32 bytes")
            .path
    };

    let original = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen ro");
        vol.read_file(&target_path).expect("read original")
    };
    assert!(original.len() >= 32);

    let payload: [u8; 16] = *b"ARFW_INPLACE_OK!";
    let write_offset: u64 = 8;

    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open volume rw");
        let n = vol
            .write_at(&target_path, write_offset, &payload)
            .expect("write_at succeeds");
        assert_eq!(n, payload.len() as u64);
    }

    // Reopen and re-read; spliced bytes must match payload, surrounding
    // bytes must be untouched
    let after = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen ro after write");
        vol.read_file(&target_path).expect("read after write")
    };
    assert_eq!(after.len(), original.len(), "size must not change");
    assert_eq!(
        &after[write_offset as usize..write_offset as usize + payload.len()],
        &payload[..],
        "spliced range mismatch"
    );
    assert_eq!(
        &after[..write_offset as usize],
        &original[..write_offset as usize],
        "bytes before the splice were modified"
    );
    assert_eq!(
        &after[write_offset as usize + payload.len()..],
        &original[write_offset as usize + payload.len()..],
        "bytes after the splice were modified"
    );

    // The structural verifier must remain happy
    let mut file = std::fs::File::open(&cloned.path).expect("reopen ro for verify");
    let report = verify_image(&mut file).expect("verify after in-place write");
    assert!(report.volumes >= 1);
    assert!(report.btree_nodes_visited > 0);
}

#[test]
fn write_at_rejects_writes_past_eof() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("write_at_rejects_writes_past_eof");
            return;
        }
    };

    let (target_path, file_size) = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open volume");
        let walk = vol.walk().expect("walk");
        let entry = walk
            .into_iter()
            .find(|e| e.entry.kind == EntryKind::File && e.entry.size >= 4)
            .expect("fixture has at least one file");
        (entry.path, entry.entry.size)
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cloned.path)
        .expect("open rw");
    let mut vol = ApfsVolume::open(file).expect("open volume rw");
    let res = vol.write_at(&target_path, file_size + 1, b"oops");
    assert!(res.is_err(), "write past EOF must fail");
}

#[test]
fn write_at_truncates_to_remaining_size_within_eof() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("write_at_truncates_to_remaining_size_within_eof");
            return;
        }
    };

    let (target_path, file_size) = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open");
        let walk = vol.walk().expect("walk");
        let e = walk
            .into_iter()
            .filter(|e| e.entry.kind == EntryKind::File && e.entry.size >= 32)
            .max_by_key(|e| e.entry.size)
            .expect("fixture has a usable file");
        (e.path, e.entry.size)
    };

    let original = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
        vol.read_file(&target_path).expect("read")
    };

    let last_two_offset = file_size - 2;
    let payload = [0xAAu8; 32];

    let written = {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open vol rw");
        vol.write_at(&target_path, last_two_offset, &payload)
            .expect("partial write succeeds")
    };
    assert_eq!(written, 2, "write must clip to remaining EOF");

    let after = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
        vol.read_file(&target_path).expect("re-read")
    };
    assert_eq!(after.len(), original.len(), "size unchanged");
    assert_eq!(&after[last_two_offset as usize..], &[0xAA, 0xAA]);
}
