pub mod apfs;

// Windows-only modules; the WinFSP host and Win32 device APIs are not
// available on other platforms, but `apfs` parses fine anywhere so we keep
// it cross-platform for tests + tooling
#[cfg(windows)]
pub mod device_monitor;
#[cfg(windows)]
pub mod device_watcher;
#[cfg(windows)]
pub mod disk;
#[cfg(windows)]
pub mod driver;
#[cfg(windows)]
pub mod error;
#[cfg(windows)]
pub mod mount_manager;
#[cfg(windows)]
pub mod utils;
