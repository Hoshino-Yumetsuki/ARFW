//! Integration test for the spaceman parser + bitmap allocator
mod common;

use arfw::apfs::ApfsVolume;
use arfw::apfs::checkpoint::resolve_ephemeral;
use arfw::apfs::spaceman::SpaceManager;
use arfw::apfs::superblock::{find_latest_nxsb, read_nxsb};
use arfw::apfs::verify::verify_image;

#[test]
fn spaceman_opens_and_reports_free_blocks() {
    let mut reader = match common::open_fixture() {
        Some(r) => r,
        None => {
            common::skip_no_fixture("spaceman_opens_and_reports_free_blocks");
            return;
        }
    };
    let nxsb = read_nxsb(&mut reader).unwrap();
    let nxsb = find_latest_nxsb(&mut reader, &nxsb).unwrap();
    let bs = nxsb.block_size;
    let sm_paddr =
        resolve_ephemeral(&mut reader, &nxsb, nxsb.spaceman_oid).expect("resolve spaceman");

    let sm = SpaceManager::open(&mut reader, sm_paddr, bs).expect("open spaceman");
    eprintln!(
        "spaceman: total_blocks={} free={} cibs={} chunks={}",
        sm.spaceman.main_block_count(),
        sm.spaceman.main_free_count(),
        sm.cibs.len(),
        sm.bitmaps.len(),
    );
    assert!(sm.spaceman.main_block_count() > 0);
    assert!(sm.spaceman.main_free_count() > 0);
    assert!(sm.spaceman.main_free_count() < sm.spaceman.main_block_count());
}

#[test]
fn volume_info_reports_container_space_from_spaceman() {
    let reader = match common::open_fixture() {
        Some(r) => r,
        None => {
            common::skip_no_fixture("volume_info_reports_container_space_from_spaceman");
            return;
        }
    };

    let volume = ApfsVolume::open(reader).expect("open APFS volume");
    let info = volume.volume_info();

    assert!(info.total_bytes > 0);
    assert!(info.free_bytes > 0);
    assert!(info.free_bytes < info.total_bytes);
    assert_eq!(info.used_bytes, info.total_bytes - info.free_bytes);
}

#[test]
fn spaceman_alloc_block_flips_bitmap() {
    let mut reader = match common::open_fixture() {
        Some(r) => r,
        None => {
            common::skip_no_fixture("spaceman_alloc_block_flips_bitmap");
            return;
        }
    };
    let nxsb = read_nxsb(&mut reader).unwrap();
    let nxsb = find_latest_nxsb(&mut reader, &nxsb).unwrap();
    let sm_paddr = resolve_ephemeral(&mut reader, &nxsb, nxsb.spaceman_oid).unwrap();
    let mut sm = SpaceManager::open(&mut reader, sm_paddr, nxsb.block_size).unwrap();

    let initial_free = sm.spaceman.main_free_count();
    let p = sm.alloc_block().expect("alloc block");
    eprintln!("allocated paddr={p}");

    assert_eq!(sm.is_block_used(p), Some(true));
    assert_eq!(sm.spaceman.main_free_count(), initial_free - 1);
    assert!(!sm.dirty_bitmaps().is_empty());
    assert!(p > 0 && p < sm.spaceman.main_block_count());

    let p2 = sm.alloc_block().expect("alloc block 2");
    assert_ne!(p, p2);
    assert_eq!(sm.spaceman.main_free_count(), initial_free - 2);
}

#[test]
fn spaceman_pristine_image_still_validates() {
    let mut reader = match common::open_fixture() {
        Some(r) => r,
        None => {
            common::skip_no_fixture("spaceman_pristine_image_still_validates");
            return;
        }
    };
    let nxsb = read_nxsb(&mut reader).unwrap();
    let nxsb = find_latest_nxsb(&mut reader, &nxsb).unwrap();
    let sm_paddr = resolve_ephemeral(&mut reader, &nxsb, nxsb.spaceman_oid).unwrap();
    let _sm = SpaceManager::open(&mut reader, sm_paddr, nxsb.block_size).unwrap();
    drop(_sm);
    verify_image(&mut reader).expect("post-open verify");
}
