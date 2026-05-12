use crate::error::{Error, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::IOCTL_DISK_GET_DRIVE_LAYOUT_EX;
use windows::core::PCSTR;

/// RAII wrapper for a Windows HANDLE that calls CloseHandle on drop
/// Guarantees the handle is closed on both success and error paths
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid open HANDLE created by CreateFileA
        // CloseHandle is called exactly once here in Drop
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// APFS partition type GUID: 7C3457EF-0000-11AA-AA11-00306543ECAC
const APFS_PARTITION_GUID: [u8; 16] = [
    0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApfsPartition {
    pub disk_number: u32,
    pub partition_number: u32,
    pub device_path: String,
    pub offset: u64,
    pub size: u64,
}

pub struct DeviceMonitor;

impl DeviceMonitor {
    pub fn scan_apfs_partitions() -> Result<Vec<ApfsPartition>> {
        let mut partitions = Vec::new();

        // Scan PhysicalDrive0 through PhysicalDrive99
        for disk_num in 0..100 {
            let disk_path = format!(r"\\.\PhysicalDrive{}", disk_num);

            match Self::scan_disk_for_apfs(&disk_path, disk_num) {
                Ok(mut disk_partitions) => partitions.append(&mut disk_partitions),
                Err(_) => continue, // Skip disks we can't open
            }
        }

        Ok(partitions)
    }

    fn scan_disk_for_apfs(disk_path: &str, disk_num: u32) -> Result<Vec<ApfsPartition>> {
        // OwnedHandle ensures CloseHandle is called on both success and error paths
        let handle = Self::open_disk(disk_path)?;
        Self::read_gpt_partitions(handle.as_raw(), disk_num)
    }

    fn open_disk(path: &str) -> Result<OwnedHandle> {
        let path_cstr = format!("{}\0", path);

        // SAFETY: `path_cstr` is a null-terminated byte string that outlives
        // this synchronous CreateFileA call. CreateFileA does not retain the
        // pointer after returning
        let handle = unsafe {
            CreateFileA(
                PCSTR(path_cstr.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        if handle.is_invalid() {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        Ok(OwnedHandle(handle))
    }

    fn read_gpt_partitions(handle: HANDLE, disk_num: u32) -> Result<Vec<ApfsPartition>> {
        #[repr(C)]
        struct DRIVE_LAYOUT_INFORMATION_EX {
            partition_style: u32,
            partition_count: u32,
            _union: [u8; 40],
            partition_entry: [PARTITION_INFORMATION_EX; 128],
        }

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct PARTITION_INFORMATION_EX {
            partition_style: u32,
            starting_offset: i64,
            partition_length: i64,
            partition_number: u32,
            rewrite_partition: u8,
            _padding: [u8; 3],
            gpt_partition_type: [u8; 16],
            gpt_partition_id: [u8; 16],
            gpt_attributes: u64,
            gpt_name: [u16; 36],
        }

        // SAFETY: DRIVE_LAYOUT_INFORMATION_EX and PARTITION_INFORMATION_EX
        // contain only integer/array fields; all-zeros is a valid bit pattern
        // and the struct is immediately overwritten by DeviceIoControl before
        // any field is read
        let mut layout: DRIVE_LAYOUT_INFORMATION_EX = unsafe { std::mem::zeroed() };
        let mut bytes_returned = 0u32;

        // SAFETY: `handle` is a valid open disk handle. `layout` lives for the
        // duration of this call and its size matches the output buffer length
        // we advertise to the kernel. The type-erased `*mut _` cast is the
        // standard pattern for DeviceIoControl output buffers
        unsafe {
            let result = DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                None,
                0,
                Some(&mut layout as *mut _ as *mut _),
                std::mem::size_of::<DRIVE_LAYOUT_INFORMATION_EX>() as u32,
                Some(&mut bytes_returned),
                None,
            );

            if result.is_err() {
                return Ok(Vec::new());
            }
        }

        let mut apfs_partitions = Vec::new();

        // Cap iteration at the array capacity (128) to prevent out-of-bounds
        // access if the OS reports a partition_count larger than our fixed-size
        // partition_entry array
        let count = (layout.partition_count as usize).min(128);
        for i in 0..count {
            let partition = &layout.partition_entry[i];

            if partition.partition_style == 1 && partition.gpt_partition_type == APFS_PARTITION_GUID
            {
                apfs_partitions.push(ApfsPartition {
                    disk_number: disk_num,
                    partition_number: partition.partition_number,
                    device_path: format!(r"\\.\PhysicalDrive{}", disk_num),
                    offset: partition.starting_offset as u64,
                    size: partition.partition_length as u64,
                });
            }
        }

        Ok(apfs_partitions)
    }

    pub fn find_available_drive_letters() -> Vec<char> {
        let mut available = Vec::new();

        for letter in b'D'..=b'Z' {
            let drive_path = format!("{}:\\", letter as char);
            let path_wide: Vec<u16> = drive_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // SAFETY: `path_wide` is a null-terminated UTF-16 Vec<u16> that
            // outlives this synchronous GetDriveTypeW call. The function does
            // not retain the pointer after returning
            unsafe {
                use windows::Win32::Storage::FileSystem::GetDriveTypeW;
                let drive_type = GetDriveTypeW(windows::core::PCWSTR(path_wide.as_ptr()));

                if drive_type == 1 {
                    available.push(letter as char);
                }
            }
        }

        available
    }
}
