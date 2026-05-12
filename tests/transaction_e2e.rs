//! End-to-end transaction commit + reopen test using the on-disk fixture
mod common;

use arfw::apfs::ApfsVolume;
use arfw::apfs::verify::verify_image;

#[test]
fn nxsb_rotation_keeps_image_valid() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("nxsb_rotation_keeps_image_valid");
            return;
        }
    };

    let target = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open ro view");
        vol.walk()
            .expect("walk")
            .into_iter()
            .find(|e| e.entry.kind == arfw::apfs::EntryKind::File)
            .expect("fixture has at least one file")
            .path
    };

    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .unwrap();
        let mut vol = ApfsVolume::open(file).expect("open rw");
        vol.set_inode_times(&target, None, Some(1_650_000_000_000_000_000), None, None)
            .expect("commit timestamps");
    }

    let mut file = std::fs::File::open(&cloned.path).expect("reopen ro");
    let report = verify_image(&mut file).expect("verify after commit");
    assert!(report.volumes >= 1);
    assert!(report.btree_nodes_visited > 0);
}
