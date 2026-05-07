/// Convert APFS timestamp (nanoseconds since Unix epoch) to Windows FILETIME
/// (100-nanosecond intervals since 1601-01-01)
pub fn apfs_time_to_filetime(apfs_time: i64) -> u64 {
    // Unix epoch (1970-01-01) in FILETIME units
    const UNIX_EPOCH_FILETIME: u64 = 116444736000000000;

    // Convert nanoseconds to 100-nanosecond intervals
    let intervals = (apfs_time / 100) as u64;

    UNIX_EPOCH_FILETIME + intervals
}

/// Convert UTF-8 path to UTF-16 for Windows
pub fn path_to_wide(path: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Convert UTF-16 path from Windows to UTF-8
pub fn wide_to_path(wide: &[u16]) -> String {
    use std::os::windows::ffi::OsStringExt;
    let os_string = std::ffi::OsString::from_wide(
        wide.iter()
            .take_while(|&&c| c != 0)
            .copied()
            .collect::<Vec<_>>()
            .as_slice(),
    );
    os_string.to_string_lossy().to_string()
}
