//! Smoke for `ApfsVolume::unlink_file`: remove a regular file in place and
//! confirm the catalog + verifier remain consistent
mod common;

use arfw::apfs::{ApfsVolume, EntryKind, verify::verify_image};

#[test]
fn unlink_removes_file_and_decrements_parent() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone"),
        None => {
            common::skip_no_fixture("unlink_removes_file_and_decrements_parent");
            return;
        }
    };

    // Find a regular file with nlink == 1 and capture its parent's
    // pre-unlink nchildren so we can confirm the decrement
    let (target_path, parent_path, parent_oid_pre) = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open");
        let walk = vol.walk().expect("walk");
        let entry = walk
            .into_iter()
            .find(|e| {
                if e.entry.kind != EntryKind::File {
                    return false;
                }
                if let Ok(s) = {
                    let mut v = ApfsVolume::open(&cloned.file).expect("reopen");
                    v.stat(&e.path)
                } {
                    s.nlink == 1
                } else {
                    false
                }
            })
            .expect("fixture has at least one nlink==1 file");
        let parent = if let Some(idx) = entry.path.rfind('/') {
            if idx == 0 {
                "/".to_string()
            } else {
                entry.path[..idx].to_string()
            }
        } else {
            "/".to_string()
        };
        let parent_stat = vol.stat(&parent).expect("parent stat");
        (entry.path, parent, parent_stat.nlink)
    };

    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open vol rw");
        vol.unlink_file(&target_path).expect("unlink succeeds");
    }

    // The file no longer exists
    {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
        let res = vol.stat(&target_path);
        assert!(res.is_err(), "stat after unlink should fail");
    }

    // Parent's nchildren decremented by exactly one
    {
        let mut vol = ApfsVolume::open(&cloned.file).expect("reopen");
        let parent_post = vol.stat(&parent_path).expect("parent stat after");
        assert_eq!(
            parent_post.nlink + 1,
            parent_oid_pre,
            "parent nchildren did not decrement"
        );
    }

    // Verifier remains happy
    let mut file = std::fs::File::open(&cloned.path).expect("reopen for verify");
    let report = verify_image(&mut file).expect("verify after unlink");
    assert!(report.volumes >= 1);
    assert!(report.btree_nodes_visited > 0);
}

#[test]
fn unlink_rejects_directory() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone"),
        None => {
            common::skip_no_fixture("unlink_rejects_directory");
            return;
        }
    };

    let dir_path = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open");
        let walk = vol.walk().expect("walk");
        walk.into_iter()
            .find(|e| e.entry.kind == EntryKind::Directory && e.path != "/")
            .expect("fixture has a subdirectory")
            .path
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cloned.path)
        .expect("open rw");
    let mut vol = ApfsVolume::open(file).expect("open vol rw");
    assert!(vol.unlink_file(&dir_path).is_err());
}

#[test]
fn unlink_rejects_missing_path() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone"),
        None => {
            common::skip_no_fixture("unlink_rejects_missing_path");
            return;
        }
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cloned.path)
        .expect("open rw");
    let mut vol = ApfsVolume::open(file).expect("open vol rw");
    assert!(vol.unlink_file("/definitely-not-here.txt").is_err());
}
