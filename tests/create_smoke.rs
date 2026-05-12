//! Smoke tests for `ApfsVolume::create_file` / `create_directory`:
//! a fresh entry must show up in `walk` and the image must still verify
mod common;

use arfw::apfs::{ApfsVolume, EntryKind, verify::verify_image};

#[test]
fn create_file_adds_entry_under_root() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("create_file_adds_entry_under_root");
            return;
        }
    };
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open volume rw");
        let oid = vol.create_file("/brand_new.txt").expect("create_file");
        assert!(oid > 0);
    }
    let mut vol = ApfsVolume::open(&cloned.file).expect("reopen ro");
    let walk = vol.walk().expect("walk");
    let found = walk
        .into_iter()
        .any(|e| e.path == "/brand_new.txt" && e.entry.kind == EntryKind::File);
    assert!(found, "/brand_new.txt should appear after create_file");
    let mut f = std::fs::File::open(&cloned.path).expect("reopen for verify");
    verify_image(&mut f).expect("image still verifies");
}

#[test]
fn create_directory_then_file_inside_it() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("create_directory_then_file_inside_it");
            return;
        }
    };
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open volume rw");
        vol.create_directory("/newdir").expect("mkdir");
        vol.create_file("/newdir/inner.txt").expect("create inside");
    }
    let mut vol = ApfsVolume::open(&cloned.file).expect("reopen ro");
    let walk = vol.walk().expect("walk");
    let dir_ok = walk.iter().any(|e| e.path == "/newdir" && e.entry.kind == EntryKind::Directory);
    let file_ok = walk
        .iter()
        .any(|e| e.path == "/newdir/inner.txt" && e.entry.kind == EntryKind::File);
    assert!(dir_ok && file_ok, "newdir + inner.txt must both exist");
    let mut f = std::fs::File::open(&cloned.path).expect("reopen for verify");
    verify_image(&mut f).expect("image still verifies");
}

#[test]
fn create_file_rejects_duplicate() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("create_file_rejects_duplicate");
            return;
        }
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cloned.path)
        .expect("open rw");
    let mut vol = ApfsVolume::open(file).expect("open volume rw");
    vol.create_file("/dupe.txt").expect("first create");
    let err = vol.create_file("/dupe.txt");
    assert!(err.is_err(), "second create must fail");
}
