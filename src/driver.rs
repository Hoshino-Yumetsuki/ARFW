use crate::disk::DiskReader;
use crate::error::{Error, Result};
use apfs::{ApfsVolume, EntryKind};
use std::io::{BufReader, Read, Seek};
use std::sync::{Arc, Mutex};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY};
use winfsp::filesystem::{
    DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::{FspError, U16CStr};

pub struct ApfsDriver {
    volume: Arc<Mutex<ApfsVolume<BufReader<DiskReader>>>>,
    disk_size: u64,
}

pub struct ApfsFileContext {
    path: String,
    dir_buffer: winfsp::filesystem::DirBuffer,
}

impl ApfsDriver {
    pub fn new(mut disk: DiskReader) -> Result<Self> {
        // Read actual APFS container size from superblock
        let disk_size = disk
            .read_apfs_container_size()
            .unwrap_or_else(|_| disk.size());

        // Read block size from container superblock
        let mut buffer = vec![0u8; 4096];
        disk.seek(std::io::SeekFrom::Start(0)).ok();
        disk.read_exact(&mut buffer).ok();
        let reader = BufReader::new(disk);
        let volume = ApfsVolume::open(reader).map_err(|e| Error::Apfs(e.to_string()))?;

        Ok(Self {
            volume: Arc::new(Mutex::new(volume)),
            disk_size,
        })
    }

    fn u16_to_path(&self, u16_path: &U16CStr) -> String {
        u16_path.to_string_lossy().replace('\\', "/")
    }

    fn apfs_time_to_filetime(&self, nanos: i64) -> u64 {
        const UNIX_EPOCH_IN_FILETIME: u64 = 116444736000000000;
        let intervals = (nanos / 100) as u64;
        UNIX_EPOCH_IN_FILETIME + intervals
    }

    fn entry_kind_to_attributes(&self, kind: EntryKind) -> u32 {
        match kind {
            EntryKind::Directory => FILE_ATTRIBUTE_DIRECTORY.0,
            _ => FILE_ATTRIBUTE_READONLY.0,
        }
    }
}

impl FileSystemContext for ApfsDriver {
    type FileContext = ApfsFileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = self.u16_to_path(file_name);
        let mut vol = self.volume.lock().unwrap();

        let stat = vol
            .stat(&path)
            .map_err(|_| FspError::NTSTATUS(0xC0000034u32 as i32))?; // STATUS_OBJECT_NAME_NOT_FOUND

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: self.entry_kind_to_attributes(stat.kind),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = self.u16_to_path(file_name);
        let mut vol = self.volume.lock().unwrap();

        let stat = vol
            .stat(&path)
            .map_err(|_| FspError::NTSTATUS(0xC0000034u32 as i32))?;

        let info: &mut FileInfo = file_info.as_mut();
        info.file_attributes = self.entry_kind_to_attributes(stat.kind);
        info.file_size = stat.size;
        info.allocation_size = (stat.size + 4095) & !4095;
        info.creation_time = self.apfs_time_to_filetime(stat.create_time);
        info.last_access_time = self.apfs_time_to_filetime(stat.modify_time);
        info.last_write_time = self.apfs_time_to_filetime(stat.modify_time);
        info.change_time = self.apfs_time_to_filetime(stat.modify_time);
        info.index_number = stat.oid;

        Ok(ApfsFileContext {
            path,
            dir_buffer: winfsp::filesystem::DirBuffer::new(),
        })
    }

    fn close(&self, _context: Self::FileContext) {}

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let mut vol = self.volume.lock().unwrap();
        let mut reader = vol
            .open_file(&context.path)
            .map_err(|_| FspError::NTSTATUS(0xC0000022u32 as i32))?; // STATUS_ACCESS_DENIED

        std::io::Seek::seek(&mut reader, std::io::SeekFrom::Start(offset))
            .map_err(|_| FspError::NTSTATUS(0xC0000011u32 as i32))?; // STATUS_END_OF_FILE

        let bytes_read = reader
            .read(buffer)
            .map_err(|_| FspError::NTSTATUS(0xC0000011u32 as i32))?;

        Ok(bytes_read as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // If marker is set, we've already returned all entries - return 0 to end enumeration
        if !marker.is_none() {
            return Ok(0);
        }

        let mut vol = self.volume.lock().unwrap();
        let entries = vol
            .list_directory(&context.path)
            .map_err(|_| FspError::NTSTATUS(0xC0000103u32 as i32))?;
        drop(vol);

        // Acquire directory buffer from context
        {
            let lock = context.dir_buffer.acquire(marker.is_none(), None)?;

            // Write "." and ".."
            let mut dir_info = winfsp::filesystem::DirInfo::<255>::new();
            dir_info.reset();
            dir_info.file_info_mut().file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            dir_info.set_name(".")?;
            lock.write(&mut dir_info)?;

            let mut dir_info = winfsp::filesystem::DirInfo::<255>::new();
            dir_info.reset();
            dir_info.file_info_mut().file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            dir_info.set_name("..")?;
            lock.write(&mut dir_info)?;

            // Write all entries
            for entry in entries {
                let mut dir_info = winfsp::filesystem::DirInfo::<255>::new();
                dir_info.reset();

                // Set name first (without null terminator, matching ntptfs pattern)
                let name_utf16: Vec<u16> = entry.name.encode_utf16().collect();
                dir_info.set_name_raw(&name_utf16[..])?;

                // Then set file info
                let info = dir_info.file_info_mut();
                info.file_attributes = self.entry_kind_to_attributes(entry.kind);
                info.file_size = entry.size;
                info.allocation_size = (entry.size + 4095) & !4095;
                info.creation_time = self.apfs_time_to_filetime(entry.create_time);
                info.last_access_time = self.apfs_time_to_filetime(entry.modify_time);
                info.last_write_time = self.apfs_time_to_filetime(entry.modify_time);
                info.change_time = self.apfs_time_to_filetime(entry.modify_time);
                info.index_number = entry.oid;

                lock.write(&mut dir_info)?;
            }
        }

        // Read all entries from context's directory buffer
        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut vol = self.volume.lock().unwrap();
        let stat = vol
            .stat(&context.path)
            .map_err(|_| FspError::NTSTATUS(0xC0000034u32 as i32))?;

        file_info.file_attributes = self.entry_kind_to_attributes(stat.kind);
        file_info.file_size = stat.size;
        file_info.allocation_size = (stat.size + 4095) & !4095;
        file_info.creation_time = self.apfs_time_to_filetime(stat.create_time);
        file_info.last_access_time = self.apfs_time_to_filetime(stat.modify_time);
        file_info.last_write_time = self.apfs_time_to_filetime(stat.modify_time);
        file_info.change_time = self.apfs_time_to_filetime(stat.modify_time);
        file_info.index_number = stat.oid;

        Ok(())
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let vol = self.volume.lock().unwrap();
        let info = vol.volume_info();

        out_volume_info.total_size = self.disk_size;
        out_volume_info.free_size = 0;
        out_volume_info.set_volume_label(&info.name);

        Ok(())
    }
}
