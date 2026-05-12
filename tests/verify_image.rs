//! End-to-end structural verifier test against the on-disk APFS fixture
mod common;

use arfw::apfs::verify::verify_image;

#[test]
fn verify_pristine_fixture() {
    let mut reader = match common::open_fixture() {
        Some(r) => r,
        None => {
            common::skip_no_fixture("verify_pristine_fixture");
            return;
        }
    };
    let report = verify_image(&mut reader).expect("verify pristine image");
    assert!(report.volumes >= 1);
    assert!(report.btree_nodes_visited > 0);
    assert!(report.max_xid > 0);
    eprintln!("verify report: {report:?}");
}

#[test]
fn verify_writable_clone_matches() {
    let cloned = match common::clone_fixture() {
        Some(c) => c.expect("clone fixture"),
        None => {
            common::skip_no_fixture("verify_writable_clone_matches");
            return;
        }
    };
    let mut file = cloned.file;
    let report = verify_image(&mut file).expect("verify clone");
    assert!(report.volumes >= 1);
    assert!(report.btree_nodes_visited > 0);
}
