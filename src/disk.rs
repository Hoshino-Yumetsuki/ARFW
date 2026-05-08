use crate::error::{Error, Result};
use std::io::{Read, Seek, SeekFrom};
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, SetFilePointerEx, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_CURRENT,
    FILE_END, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY_EX;
use windows::Win32::System::IO::DeviceIoControl;

const APFS_BLOCK_SIZE: usize = 4096;

pub struct DiskReader {
    handle: HANDLE,
    size: u64,
    offset: u64,
    device_path: String,
}

impl DiskReader {
    pub fn open(path: &str) -> Result<Self> {
        Self::open_with_offset(path, 0)
    }

    pub fn open_with_offset(path: &str, offset: u64) -> Result<Self> {
        let path_cstr = format!("{}\0", path);

        // SAFETY: `path_cstr` is a null-terminated byte string that outlives
        // this synchronous CreateFileA call. CreateFileA does not retain the
        // pointer after returning.
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

        let size = Self::get_disk_size(handle).unwrap_or(0);

        Ok(Self {
            handle,
            size,
            offset,
            device_path: path.to_string(),
        })
    }

    /// Open a second independent handle to the same device for raw positioned reads.
    /// offset=0 — callers add partition offset explicitly.
    pub fn reopen_raw(&self) -> Result<Self> {
        Self::open_with_offset(&self.device_path, 0)
    }

    /// Open a second independent handle with the same partition offset.
    pub fn reopen(&self) -> Result<Self> {
        Self::open_with_offset(&self.device_path, self.offset)
    }

    /// Returns the partition offset in bytes.
    pub fn partition_offset(&self) -> u64 {
        self.offset
    }

    /// Read bytes from an absolute disk offset using SetFilePointerEx + ReadFile.
    /// Handles sector alignment automatically — raw disk reads must be sector-aligned.
    pub fn read_at_absolute(&self, absolute_offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let sector_offset = (absolute_offset % SECTOR_SIZE as u64) as usize;
        let aligned_offset = absolute_offset - sector_offset as u64;
        let total_needed = sector_offset + buf.len();
        let aligned_len = (total_needed + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;

        let mut tmp = vec![0u8; aligned_len];
        let mut bytes_read = 0u32;

        // SAFETY: `aligned_offset as i64` is safe for any disk < 9.2 EB (not
        // a practical concern). SetFilePointerEx is synchronous and does not
        // retain any pointer after returning.
        unsafe {
            SetFilePointerEx(self.handle, aligned_offset as i64, None, FILE_BEGIN)
                .map_err(|e| Error::Io(std::io::Error::other(e)))?;

            ReadFile(self.handle, Some(&mut tmp), Some(&mut bytes_read), None)
                .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        }

        let available = (bytes_read as usize).saturating_sub(sector_offset);
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&tmp[sector_offset..sector_offset + to_copy]);

        Ok(to_copy)
    }

    /// Read bytes from a partition-relative offset.
    pub fn read_at(&self, physical_offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read_at_absolute(self.offset + physical_offset, buf)
    }

    fn get_disk_size(handle: HANDLE) -> Result<u64> {
        // Query disk geometry using IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.
        // DISK_GEOMETRY_EX is a variable-length struct; we only need the fixed
        // header (geometry + disk_size), so we define a minimal repr(C) overlay.
        #[repr(C)]
        struct DISK_GEOMETRY_EX {
            geometry: [u8; 24], // DISK_GEOMETRY (fixed-size header)
            disk_size: i64,
            data: [u8; 1],
        }

        // SAFETY: DISK_GEOMETRY_EX contains only integer/array fields; all-zeros
        // is a valid bit pattern and the struct is immediately overwritten by
        // DeviceIoControl before any field is read.
        let mut geometry = unsafe { std::mem::zeroed::<DISK_GEOMETRY_EX>() };
        let mut bytes_returned = 0u32;

        // SAFETY: `handle` is a valid open disk handle passed by the caller.
        // `geometry` lives for the duration of this call and its size matches
        // the output buffer length we advertise to the kernel.
        let result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(&mut geometry as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_err() || bytes_returned == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        // disk_size is documented as always non-negative; guard against a
        // malformed driver response that could wrap on the cast.
        if geometry.disk_size < 0 {
            return Err(Error::Io(std::io::Error::other(
                "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX returned negative disk size",
            )));
        }

        Ok(geometry.disk_size as u64)
    }

    pub fn read_block(&mut self, block_num: u64, buffer: &mut [u8]) -> Result<usize> {
        let offset = block_num * APFS_BLOCK_SIZE as u64;
        self.seek(SeekFrom::Start(offset))?;
        self.read(buffer).map_err(Into::into)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    // Read APFS container superblock to get actual volume size
    pub fn read_apfs_container_size(&mut self) -> Result<u64> {
        // APFS container superblock is at block 0
        let mut buffer = vec![0u8; 4096];
        self.seek(SeekFrom::Start(0))?;
        self.read_exact(&mut buffer)?;

        // Parse nx_superblock_t structure
        // Offset 36: nx_block_size (u32)
        // Offset 40: nx_block_count (u64)
        let block_size =
            u32::from_le_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]) as u64;
        let block_count = u64::from_le_bytes([
            buffer[40], buffer[41], buffer[42], buffer[43], buffer[44], buffer[45], buffer[46],
            buffer[47],
        ]);

        Ok(block_count * block_size)
    }

    // Read APFS volume space info (alloced and freed blocks)
    pub fn read_apfs_volume_space(&mut self) -> Result<(u64, u64)> {
        // Read container superblock (block 0)
        let mut buffer = vec![0u8; 4096];
        self.seek(SeekFrom::Start(0))?;
        self.read_exact(&mut buffer)?;

        // Extract block size first
        let block_size =
            u32::from_le_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]) as u64;

        // Extract nx_omap_oid (offset 160) and nx_fs_oid[0] (offset 184)
        let nx_omap_oid = u64::from_le_bytes([
            buffer[160],
            buffer[161],
            buffer[162],
            buffer[163],
            buffer[164],
            buffer[165],
            buffer[166],
            buffer[167],
        ]);
        let volume_oid = u64::from_le_bytes([
            buffer[184],
            buffer[185],
            buffer[186],
            buffer[187],
            buffer[188],
            buffer[189],
            buffer[190],
            buffer[191],
        ]);

        // Check if volume OID is valid
        if volume_oid == 0 {
            return Err(Error::Apfs("No volume found in container".to_string()).into());
        }

        // Read object map (omap_phys_t) at nx_omap_oid
        self.seek(SeekFrom::Start(nx_omap_oid * block_size))?;
        self.read_exact(&mut buffer)?;

        // Extract om_tree_oid (offset 48)
        let om_tree_oid = u64::from_le_bytes([
            buffer[48], buffer[49], buffer[50], buffer[51], buffer[52], buffer[53], buffer[54],
            buffer[55],
        ]);

        // Read B-tree root node
        self.seek(SeekFrom::Start(om_tree_oid * block_size))?;
        self.read_exact(&mut buffer)?;

        // Search B-tree for volume_oid
        let volume_paddr = self.search_btree_node(&buffer, volume_oid)?;

        // Read volume superblock (apfs_superblock_t) at volume_paddr
        self.seek(SeekFrom::Start(volume_paddr * block_size))?;
        self.read_exact(&mut buffer)?;

        // Extract apfs_total_blocks_alloced (offset 224) and apfs_total_blocks_freed (offset 232)
        let alloced = u64::from_le_bytes([
            buffer[224],
            buffer[225],
            buffer[226],
            buffer[227],
            buffer[228],
            buffer[229],
            buffer[230],
            buffer[231],
        ]);
        let freed = u64::from_le_bytes([
            buffer[232],
            buffer[233],
            buffer[234],
            buffer[235],
            buffer[236],
            buffer[237],
            buffer[238],
            buffer[239],
        ]);

        Ok((alloced, freed))
    }

    // Optimized B-tree node search - 8-byte aligned scan
    fn search_btree_node(&self, node: &[u8], target_oid: u64) -> Result<u64> {
        // Scan btn_data area in 8-byte increments (OIDs are 8-byte aligned)
        // Start from offset 72, scan in 8-byte steps
        let mut offset = 72;

        while offset + 32 <= node.len() {
            // Read potential OID at this 8-byte aligned position
            let oid = u64::from_le_bytes([
                node[offset],
                node[offset + 1],
                node[offset + 2],
                node[offset + 3],
                node[offset + 4],
                node[offset + 5],
                node[offset + 6],
                node[offset + 7],
            ]);

            if oid == target_oid {
                // Found match, read paddr from value (16 bytes after key start)
                let val_offset = offset + 16;
                if val_offset + 16 <= node.len() {
                    let paddr = u64::from_le_bytes([
                        node[val_offset + 8],
                        node[val_offset + 9],
                        node[val_offset + 10],
                        node[val_offset + 11],
                        node[val_offset + 12],
                        node[val_offset + 13],
                        node[val_offset + 14],
                        node[val_offset + 15],
                    ]);

                    // Sanity check
                    if paddr > 0 && paddr < 1000000000 {
                        return Ok(paddr);
                    }
                }
            }

            offset += 8; // Move to next 8-byte aligned position
        }

        Err(Error::Apfs("Volume OID not found in object map".to_string()).into())
    }
}

const SECTOR_SIZE: usize = 512;

impl Read for DiskReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Raw disk devices require reads to be sector-aligned in both offset and length.
        // Get current position to determine alignment.
        let mut current_pos = 0i64;
        // SAFETY: Querying the current file pointer position by seeking 0 bytes
        // from FILE_CURRENT. The output pointer `&mut current_pos` is valid for
        // the duration of this synchronous call.
        unsafe {
            SetFilePointerEx(self.handle, 0, Some(&mut current_pos), FILE_CURRENT)
                .map_err(|e| std::io::Error::other(e))?;
        }

        let pos = current_pos as u64;
        let sector_offset = (pos % SECTOR_SIZE as u64) as usize;
        let aligned_pos = pos - sector_offset as u64;

        // Round up read length to sector boundary, including any leading offset bytes.
        let total_needed = sector_offset + buf.len();
        let aligned_len = (total_needed + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;

        // Read into a sector-aligned temporary buffer.
        let mut tmp = vec![0u8; aligned_len];
        let mut bytes_read = 0u32;

        // SAFETY: Both SetFilePointerEx and ReadFile are synchronous. `tmp` is
        // a live Vec<u8> sized to `aligned_len`; the Windows crate passes its
        // pointer and length internally. The aligned_pos cast to i64 is safe for
        // any disk < 9.2 EB.
        unsafe {
            // Seek to aligned position first.
            SetFilePointerEx(self.handle, aligned_pos as i64, None, FILE_BEGIN)
                .map_err(|e| std::io::Error::other(e))?;

            ReadFile(self.handle, Some(&mut tmp), Some(&mut bytes_read), None)
                .map_err(|e| std::io::Error::other(e))?;
        }

        let available = (bytes_read as usize).saturating_sub(sector_offset);
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&tmp[sector_offset..sector_offset + to_copy]);

        // Restore file pointer to pos + to_copy.
        // SAFETY: Synchronous seek; cast to i64 is safe for any disk < 9.2 EB.
        unsafe {
            SetFilePointerEx(self.handle, (pos + to_copy as u64) as i64, None, FILE_BEGIN)
                .map_err(|e| std::io::Error::other(e))?;
        }

        Ok(to_copy)
    }
}

impl Seek for DiskReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let (distance, method) = match pos {
            SeekFrom::Start(n) => ((self.offset + n) as i64, FILE_BEGIN),
            SeekFrom::Current(n) => (n, FILE_CURRENT),
            SeekFrom::End(n) => (n, FILE_END),
        };

        let mut new_pos = 0i64;
        // SAFETY: Synchronous seek. `distance` and `method` are derived from
        // the SeekFrom argument; `new_pos` is a valid output pointer for the
        // duration of this call.
        unsafe {
            SetFilePointerEx(self.handle, distance, Some(&mut new_pos), method)
                .map_err(|e| std::io::Error::other(e))?;
        }
        Ok((new_pos as u64).saturating_sub(self.offset))
    }
}

impl Drop for DiskReader {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a valid open HANDLE created in
        // `open_with_offset`. CloseHandle is called exactly once here in Drop.
        // Errors are intentionally ignored — there is no meaningful recovery
        // action in a destructor.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: `DiskReader` owns a Windows HANDLE which is safe to move across
// threads — the OS does not associate HANDLEs with the creating thread.
// `read_at_absolute` uses SetFilePointerEx + ReadFile without OVERLAPPED, which
// is NOT concurrently safe on the same handle. All callers that share a
// DiskReader across threads (e.g. ApfsDriver) wrap it in Arc<Mutex<DiskReader>>,
// which serialises access and upholds the single-writer invariant required here.
// DiskReader must NOT be used concurrently without an external Mutex.
unsafe impl Send for DiskReader {}
