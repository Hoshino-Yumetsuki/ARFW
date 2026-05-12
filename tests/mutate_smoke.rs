//! End-to-end mutation smoke test: round-trip an inode mtime via NXSB rotation
mod common;

use arfw::apfs::ApfsVolume;

#[test]
fn round_trips_inode_mtime_via_nxsb_rotation() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("round_trips_inode_mtime_via_nxsb_rotation");
            return;
        }
    };

    let target_path = {
        let mut vol = ApfsVolume::open(&cloned.file).expect("open volume (ro view)");
        let walk = vol.walk().expect("walk");
        walk.into_iter()
            .find(|e| e.entry.kind == arfw::apfs::EntryKind::File)
            .expect("fixture has at least one file")
            .path
    };

    const SENTINEL_MTIME_NS: i64 = 1_700_000_000_000_000_000;
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cloned.path)
            .expect("open rw");
        let mut vol = ApfsVolume::open(file).expect("open volume rw");
        vol.set_inode_times(&target_path, None, Some(SENTINEL_MTIME_NS), None, None)
            .expect("set_inode_times commits");
    }

    let file = std::fs::File::open(&cloned.path).expect("reopen ro");
    let mut vol = ApfsVolume::open(file).expect("reopen volume");
    let stat = vol.stat(&target_path).expect("stat after commit");
    assert_eq!(
        stat.modify_time, SENTINEL_MTIME_NS,
        "mtime did not survive a NXSB-rotation commit cycle"
    );
}
