//! Sanity test that the generated APFS fixture is parseable end-to-end
//! Skipped when the fixture has not been built (Linux/Windows CI)
mod common;

use arfw::apfs::superblock::{NX_MAGIC, read_nxsb};

#[test]
fn fixture_opens_and_has_valid_nxsb() {
    let mut reader = match common::open_fixture() {
        Some(r) => r,
        None => {
            common::skip_no_fixture("fixture_opens_and_has_valid_nxsb");
            return;
        }
    };
    let nxsb = read_nxsb(&mut reader).expect("parse NXSB");
    assert_eq!(nxsb.magic, NX_MAGIC, "container magic mismatch");
    assert!(nxsb.block_size >= 512 && nxsb.block_size.is_power_of_two());
    assert!(nxsb.fs_oids.iter().any(|&o| o != 0));
}

#[test]
fn fixture_is_writable_clone() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("fixture_is_writable_clone");
            return;
        }
    };
    let meta = std::fs::metadata(&cloned.path).unwrap();
    assert!(meta.len() > 0);
    let original = std::fs::read(common::fixture_path()).unwrap();
    let copy = std::fs::read(&cloned.path).unwrap();
    assert_eq!(original.len(), copy.len());
    assert_eq!(original, copy);
}
