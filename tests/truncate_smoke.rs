//! Smoke for `ApfsVolume::set_logical_size` (shrink-only) and the
//! verify_image pass after a logical truncation
mod common;

use arfw::apfs::{ApfsVolume, EntryKind, verify::verify_image};

#[test]
fn set_logical_size_shrinks_in_place() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("set_logical_size_shrinks_in_place");
            return;
        }
    };

    let (target_path, original_size) = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open volume (ro view)");
        let walk = vol.walk().expect("walk");
        let entry = walk
            .into_iter()
            .filter(|e| e.entry.kind == EntryKind::File && e.entry.size >= 16)
            .max_by_key(|e| e.entry.size)
            .expect("fixture has a regular file >= 16 bytes");
        (entry.path, entry.entry.size)
    };

    let new_size = original_size / 2;

    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open volume rw");
        vol.set_logical_size(&target_path, new_size)
            .expect("shrink succeeds");
    }

    // Reopen and confirm new logical size persisted
    let stat = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
        vol.stat(&target_path).expect("stat after shrink")
    };
    assert_eq!(stat.size, new_size, "logical size did not persist");

    // Verifier still passes
    let mut file = std::fs::File::open(&cloned.path).expect("reopen for verify");
    let report = verify_image(&mut file).expect("verify after shrink");
    assert!(report.volumes >= 1);
}

#[test]
fn set_logical_size_rejects_grow() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone"),
        None => {
            common::skip_no_fixture("set_logical_size_rejects_grow");
            return;
        }
    };

    let (target_path, original_size) = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open");
        let walk = vol.walk().expect("walk");
        let entry = walk
            .into_iter()
            .find(|e| e.entry.kind == EntryKind::File)
            .expect("any file");
        (entry.path, entry.entry.size)
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cloned.path)
        .expect("open rw");
    let mut vol = ApfsVolume::open(file).expect("open volume rw");
    let res = vol.set_logical_size(&target_path, original_size + 4096);
    assert!(res.is_err(), "grow must be rejected");
}

#[test]
fn set_logical_size_noop_succeeds() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone"),
        None => {
            common::skip_no_fixture("set_logical_size_noop_succeeds");
            return;
        }
    };

    let (target_path, original_size) = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open");
        let walk = vol.walk().expect("walk");
        let entry = walk
            .into_iter()
            .find(|e| e.entry.kind == EntryKind::File)
            .expect("any file");
        (entry.path, entry.entry.size)
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cloned.path)
        .expect("open rw");
    let mut vol = ApfsVolume::open(file).expect("open volume rw");
    vol.set_logical_size(&target_path, original_size)
        .expect("no-op succeeds");
}
