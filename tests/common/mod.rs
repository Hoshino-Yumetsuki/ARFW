#![allow(dead_code)]

//! Shared test infrastructure for the arfw::apfs crate's integration tests
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

pub fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("apfs_test.raw")
}

pub fn open_fixture() -> Option<BufReader<File>> {
    let path = fixture_path();
    if !path.exists() {
        return None;
    }
    File::open(path).ok().map(BufReader::new)
}

pub fn clone_fixture() -> Option<io::Result<ClonedFixture>> {
    let src = fixture_path();
    if !src.exists() {
        return None;
    }
    Some(clone_fixture_inner(&src))
}

fn clone_fixture_inner(src: &Path) -> io::Result<ClonedFixture> {
    let dir = tempfile::tempdir()?;
    let dst = dir.path().join("apfs_clone.raw");
    fs::copy(src, &dst)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dst)?;
    Ok(ClonedFixture {
        _dir: dir,
        path: dst,
        file,
    })
}

pub struct ClonedFixture {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub file: File,
}

pub fn skip_no_fixture(test_name: &str) {
    eprintln!(
        "[arfw::apfs:{test_name}] skipped — fixture not built. Run tests/fixtures/make_fixture.sh on macOS."
    );
}
