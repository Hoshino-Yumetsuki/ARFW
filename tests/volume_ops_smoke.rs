//! Smoke tests for `ApfsVolume::unlink_directory`, `rename_file`, and
//! the grow/append paths
mod common;

use arfw::apfs::{ApfsVolume, EntryKind, verify::verify_image};

fn open_rw(p: &std::path::Path) -> ApfsVolume<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(p)
        .expect("open rw");
    ApfsVolume::open(f).expect("open volume rw")
}

#[test]
fn unlink_directory_removes_empty_dir() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("unlink_directory_removes_empty_dir");
            return;
        }
    };
    {
        let mut vol = open_rw(&cloned.path);
        vol.unlink_directory("/empty_dir").expect("rmdir");
    }
    let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
    let walk = vol.walk().expect("walk");
    assert!(
        walk.iter().all(|e| e.path != "/empty_dir"),
        "/empty_dir must be gone"
    );
    let mut f = std::fs::File::open(&cloned.path).expect("reopen");
    verify_image(&mut f).expect("image still verifies");
}

#[test]
fn unlink_directory_rejects_nonempty() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("unlink_directory_rejects_nonempty");
            return;
        }
    };
    let mut vol = open_rw(&cloned.path);
    let err = vol.unlink_directory("/sub");
    assert!(err.is_err(), "rmdir on non-empty dir must fail");
}

#[test]
fn rename_file_within_root() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("rename_file_within_root");
            return;
        }
    };
    {
        let mut vol = open_rw(&cloned.path);
        vol.rename_file("/hello.txt", "/hello_renamed.txt", false)
            .expect("rename");
    }
    let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
    let walk = vol.walk().expect("walk");
    assert!(walk.iter().any(|e| e.path == "/hello_renamed.txt"));
    assert!(walk.iter().all(|e| e.path != "/hello.txt"));
    let data = vol.read_file("/hello_renamed.txt").expect("read after rename");
    assert!(!data.is_empty());
    let mut f = std::fs::File::open(&cloned.path).expect("reopen");
    verify_image(&mut f).expect("image still verifies");
}

#[test]
fn rename_file_cross_directory() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("rename_file_cross_directory");
            return;
        }
    };
    {
        let mut vol = open_rw(&cloned.path);
        vol.rename_file("/hello.txt", "/sub/hello_moved.txt", false)
            .expect("rename");
    }
    let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
    let walk = vol.walk().expect("walk");
    assert!(walk.iter().any(|e| e.path == "/sub/hello_moved.txt"));
    assert!(walk.iter().all(|e| e.path != "/hello.txt"));
    let mut f = std::fs::File::open(&cloned.path).expect("reopen");
    verify_image(&mut f).expect("image still verifies");
}

#[test]
fn append_data_extends_file() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("append_data_extends_file");
            return;
        }
    };
    let target = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("ro");
        let walk = vol.walk().expect("walk");
        walk.into_iter()
            .find(|e| e.path == "/hello.txt" && e.entry.kind == EntryKind::File)
            .expect("hello.txt")
            .path
    };
    let original = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("ro");
        vol.read_file(&target).expect("read")
    };
    let appended: &[u8] = b"\nAPPENDED_BYTES_FROM_TEST";
    {
        let mut vol = open_rw(&cloned.path);
        let n = vol.append_data(&target, appended).expect("append");
        assert_eq!(n, appended.len() as u64);
    }
    let after = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen ro");
        vol.read_file(&target).expect("read after append")
    };
    assert_eq!(after.len(), original.len() + appended.len());
    assert_eq!(&after[..original.len()], &original[..]);
    assert_eq!(&after[original.len()..], appended);
    let mut f = std::fs::File::open(&cloned.path).expect("reopen");
    verify_image(&mut f).expect("image still verifies");
}

#[test]
fn grow_file_zero_fills_tail() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("grow_file_zero_fills_tail");
            return;
        }
    };
    let target = "/hello.txt";
    let original = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("ro");
        vol.read_file(target).expect("read")
    };
    let new_size = (original.len() + 8192) as u64;
    {
        let mut vol = open_rw(&cloned.path);
        vol.grow_file(target, new_size).expect("grow");
    }
    let after = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen ro");
        vol.read_file(target).expect("read after grow")
    };
    assert_eq!(after.len() as u64, new_size);
    assert_eq!(&after[..original.len()], &original[..]);
    assert!(after[original.len()..].iter().all(|&b| b == 0));
    let mut f = std::fs::File::open(&cloned.path).expect("reopen");
    verify_image(&mut f).expect("image still verifies");
}
