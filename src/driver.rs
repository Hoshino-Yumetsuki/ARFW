use crate::apfs::{ApfsVolume, EntryKind, FileStat};
use crate::disk::DiskReader;
use crate::error::{Error, Result};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY};
use winfsp::filesystem::{
    DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::{FspError, U16CStr};

/// Cached extent map entry: (logical_start_bytes, physical_start_bytes, length_bytes)
type ExtentEntry = (u64, u64, u64);

/// Read/write mode for an [`ApfsDriver`] mount
///
/// `ReadOnly` is the only fully-supported mode today and is the default
/// `ReadWriteUnsafe` is reserved for the in-progress write path (Phases 4-6
/// of the write plan); it does NOT currently expose any write callbacks
/// through WinFSP. Once the COW + checkpoint commit pipeline lands, this
/// flag enables the write callbacks (`write`, `create`,
/// `set_file_size`, `set_basic_info`, `rename`, `cleanup`-with-delete)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadWriteMode {
    ReadOnly,
    /// Loopback / disk-image targets only. Caller MUST also set the
    /// `ARFW_I_UNDERSTAND_DATA_LOSS=1` environment variable
    ReadWriteUnsafe,
}

/// Cached metadata for a path
#[derive(Clone)]
struct CachedStat {
    stat: FileStat,
    /// Extent map for files; empty for directories
    extent_map: Vec<ExtentEntry>,
    /// Logical file size; 0 for directories
    file_size: u64,
    /// True when extent_map was resolved via stat_and_extents()
    /// False when populated from list_directory(); extent_map is empty in that case
    extents_resolved: bool,
}

const STAT_CACHE_CAPACITY: usize = 4096;

pub struct ApfsDriver {
    /// Used exclusively for metadata operations (stat, list_directory, open)
    volume: Arc<Mutex<ApfsVolume<DiskReader>>>,
    /// Raw handle (offset=0) for positioned reads. Mutex required because
    /// SetFilePointerEx+ReadFile is not atomic
    raw_disk: Arc<Mutex<DiskReader>>,
    /// Partition offset in bytes, added to extent physical addresses before reading
    partition_offset: u64,
    /// LRU cache: path -> CachedStat
    stat_cache: Mutex<LruCache<String, CachedStat>>,
    /// Read or read/write. Currently only `ReadOnly` is honoured by the
    /// WinFSP callbacks; the `ReadWriteUnsafe` value is parsed and stored
    /// but write callbacks are not yet registered
    mode: ReadWriteMode,
}

pub struct ApfsFileContext {
    path: String,
    /// Extent map resolved once at open() time
    extent_map: Vec<ExtentEntry>,
    /// Logical file size in bytes
    file_size: u64,
    dir_buffer: winfsp::filesystem::DirBuffer,
}

impl ApfsDriver {
    pub fn new(disk: DiskReader) -> Result<Self> {
        Self::with_mode(disk, ReadWriteMode::ReadOnly)
    }

    /// Build a driver with the given read/write mode. `ReadWriteUnsafe`
    /// requires the environment variable `ARFW_I_UNDERSTAND_DATA_LOSS=1`
    pub fn with_mode(disk: DiskReader, mode: ReadWriteMode) -> Result<Self> {
        if mode == ReadWriteMode::ReadWriteUnsafe
            && std::env::var("ARFW_I_UNDERSTAND_DATA_LOSS").as_deref() != Ok("1")
        {
            return Err(Error::Apfs(
                "ReadWriteUnsafe mode requires ARFW_I_UNDERSTAND_DATA_LOSS=1 env var".into(),
            ));
        }
        let partition_offset = disk.partition_offset();
        let raw_disk = disk.reopen_raw()?;

        // The metadata-side handle drives the write path through ApfsVolume
        // In RW mode we must reopen with FILE_GENERIC_WRITE access; in RO mode
        // we keep the original read-only handle to surface a clear error if
        // anything ever calls a mutation method by accident
        let metadata_disk = if mode == ReadWriteMode::ReadWriteUnsafe {
            let path = disk.device_path().to_string();
            drop(disk);
            DiskReader::open_rw_with_offset(&path, partition_offset)?
        } else {
            disk
        };

        let volume = ApfsVolume::open(metadata_disk).map_err(|e| Error::Apfs(e.to_string()))?;

        Ok(Self {
            volume: Arc::new(Mutex::new(volume)),
            raw_disk: Arc::new(Mutex::new(raw_disk)),
            partition_offset,
            stat_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(STAT_CACHE_CAPACITY).unwrap(),
            )),
            mode,
        })
    }

    pub fn mode(&self) -> ReadWriteMode {
        self.mode
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
            _ => {
                // Surface read-only attribute only when the mount itself
                // is read-only; in RW mode pretend files are normal so
                // explorer/notepad don't refuse to overwrite
                if self.mode == ReadWriteMode::ReadOnly {
                    FILE_ATTRIBUTE_READONLY.0
                } else {
                    windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL.0
                }
            }
        }
    }

    /// Re-fill `file_info` from the cached stat after a write/truncate
    /// Falls back to a fresh `get_file_info` if the cache was evicted
    fn refresh_file_info_after_write(
        &self,
        context: &ApfsFileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(cached) = self.get_cached_stat(&context.path) {
            let ft = |n| self.apfs_time_to_filetime(n);
            let attr = |k| self.entry_kind_to_attributes(k);
            Self::fill_file_info(file_info, &cached.stat, cached.file_size, ft, attr);
            return Ok(());
        }
        let mut vol = self.volume.lock().unwrap();
        let stat = vol
            .stat(&context.path)
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        let ft = |n| self.apfs_time_to_filetime(n);
        let attr = |k| self.entry_kind_to_attributes(k);
        Self::fill_file_info(file_info, &stat, stat.size, ft, attr);
        Ok(())
    }

    fn get_cached_stat(&self, path: &str) -> Option<CachedStat> {
        self.stat_cache.lock().unwrap().get(path).cloned()
    }

    fn put_cached_stat(&self, path: String, entry: CachedStat) {
        self.stat_cache.lock().unwrap().put(path, entry);
    }

    fn logical_to_physical(extent_map: &[ExtentEntry], logical_offset: u64) -> Option<u64> {
        for &(log_start, phys_start, length) in extent_map {
            if logical_offset >= log_start && logical_offset < log_start + length {
                return Some(phys_start + (logical_offset - log_start));
            }
        }
        None
    }

    fn extent_remaining(extent_map: &[ExtentEntry], logical_offset: u64) -> u64 {
        for &(log_start, _, length) in extent_map {
            if logical_offset >= log_start && logical_offset < log_start + length {
                return (log_start + length) - logical_offset;
            }
        }
        0
    }

    fn fill_file_info(
        info: &mut FileInfo,
        stat: &FileStat,
        file_size: u64,
        filetime_fn: impl Fn(i64) -> u64,
        attr_fn: impl Fn(EntryKind) -> u32,
    ) {
        info.file_attributes = attr_fn(stat.kind);
        info.file_size = file_size;
        info.allocation_size = (file_size + 4095) & !4095;
        info.creation_time = filetime_fn(stat.create_time);
        info.last_access_time = filetime_fn(stat.modify_time);
        info.last_write_time = filetime_fn(stat.modify_time);
        info.change_time = filetime_fn(stat.modify_time);
        info.index_number = stat.oid;
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

        if path == "/" || path.is_empty() {
            return Ok(FileSecurity {
                reparse: false,
                sz_security_descriptor: 0,
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
            });
        }

        if let Some(cached) = self.get_cached_stat(&path) {
            return Ok(FileSecurity {
                reparse: false,
                sz_security_descriptor: 0,
                attributes: self.entry_kind_to_attributes(cached.stat.kind),
            });
        }

        let mut vol = self.volume.lock().unwrap();
        let (stat, extent_map, file_size) = vol
            .stat_and_extents(&path)
            .map_err(|_| FspError::NTSTATUS(0xC0000034u32 as i32))?;
        drop(vol);

        let attributes = self.entry_kind_to_attributes(stat.kind);
        self.put_cached_stat(
            path,
            CachedStat {
                stat,
                extent_map,
                file_size,
                extents_resolved: true,
            },
        );

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes,
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

        let cached = match self.get_cached_stat(&path) {
            Some(c) if c.extents_resolved || c.stat.kind == EntryKind::Directory => c,
            _ => {
                let mut vol = self.volume.lock().unwrap();
                let (stat, extent_map, file_size) = vol
                    .stat_and_extents(&path)
                    .map_err(|_| FspError::NTSTATUS(0xC0000034u32 as i32))?;
                drop(vol);
                let c = CachedStat {
                    stat,
                    extent_map,
                    file_size,
                    extents_resolved: true,
                };
                self.put_cached_stat(path.clone(), c.clone());
                c
            }
        };

        let info: &mut FileInfo = file_info.as_mut();
        let ft = |n| self.apfs_time_to_filetime(n);
        let attr = |k| self.entry_kind_to_attributes(k);
        Self::fill_file_info(info, &cached.stat, cached.file_size, ft, attr);

        Ok(ApfsFileContext {
            path,
            extent_map: cached.extent_map,
            file_size: cached.file_size,
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
        if offset >= context.file_size {
            return Ok(0);
        }

        let remaining = (context.file_size - offset) as usize;
        let to_read = buffer.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }

        // Use cached extent map + raw_disk for direct positioned reads
        // No B-tree traversal, no seek state contention with the metadata volume
        let disk = self.raw_disk.lock().unwrap();
        let mut total_read = 0usize;

        while total_read < to_read {
            let logical_pos = offset + total_read as u64;

            let physical_pos = Self::logical_to_physical(&context.extent_map, logical_pos)
                .ok_or(FspError::NTSTATUS(0xC0000011u32 as i32))?;

            let avail = Self::extent_remaining(&context.extent_map, logical_pos);
            if avail == 0 {
                break;
            }

            let chunk_size = ((to_read - total_read) as u64).min(avail) as usize;
            let abs_offset = self.partition_offset + physical_pos;

            let bytes = disk
                .read_at_absolute(abs_offset, &mut buffer[total_read..total_read + chunk_size])
                .map_err(|_| FspError::NTSTATUS(0xC0000011u32 as i32))?;

            if bytes == 0 {
                break;
            }
            total_read += bytes;
        }

        Ok(total_read as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if !marker.is_none() {
            return Ok(0);
        }

        let mut vol = self.volume.lock().unwrap();
        let entries = vol
            .list_directory(&context.path)
            .map_err(|_| FspError::NTSTATUS(0xC0000103u32 as i32))?;
        drop(vol);

        // Pre-populate stat cache with directory entries so subsequent
        // get_security_by_name + open calls hit the cache instead of B-tree
        {
            let parent = if context.path == "/" || context.path.is_empty() {
                String::new()
            } else {
                context.path.clone()
            };

            let mut cache = self.stat_cache.lock().unwrap();
            for entry in &entries {
                let child_path = if parent.is_empty() {
                    format!("/{}", entry.name)
                } else {
                    format!("{}/{}", parent, entry.name)
                };

                if !cache.contains(&child_path) {
                    let stat = FileStat {
                        oid: entry.oid,
                        kind: entry.kind,
                        size: entry.size,
                        create_time: entry.create_time,
                        modify_time: entry.modify_time,
                        uid: 0,
                        gid: 0,
                        mode: 0,
                        nlink: 1,
                    };
                    cache.put(
                        child_path,
                        CachedStat {
                            stat,
                            extent_map: Vec::new(),
                            file_size: entry.size,
                            extents_resolved: false,
                        },
                    );
                }
            }
        }

        {
            let lock = context.dir_buffer.acquire(marker.is_none(), None)?;

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

            for entry in &entries {
                let mut dir_info = winfsp::filesystem::DirInfo::<255>::new();
                dir_info.reset();

                let name_utf16: Vec<u16> = entry.name.encode_utf16().collect();
                dir_info.set_name_raw(&name_utf16[..])?;

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

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(cached) = self.get_cached_stat(&context.path) {
            let ft = |n| self.apfs_time_to_filetime(n);
            let attr = |k| self.entry_kind_to_attributes(k);
            Self::fill_file_info(file_info, &cached.stat, cached.file_size, ft, attr);
            return Ok(());
        }

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

        out_volume_info.total_size = info.total_bytes;
        out_volume_info.free_size = info.free_bytes;
        out_volume_info.set_volume_label(&info.name);

        Ok(())
    }

    // ------------------------------------------------------------------
    // Write callbacks
    //
    // All write paths are gated on `self.mode == ReadWriteUnsafe`
    // In ReadOnly mode they return STATUS_MEDIA_WRITE_PROTECTED
    //
    // Currently functional in RW mode:
    //  - `set_basic_info` — full timestamp updates via NXSB rotation
    //  - `write` — in-place data writes within current file size
    //  - `set_file_size` — accepts no-op (size unchanged) or shrink
    //  - `overwrite` — accepts no-op or shrink (`allocation_size` <= current)
    //  - `set_delete` + `cleanup` — unlink regular files (nlink == 1)
    //  - `flush` — flushes the underlying device on demand
    //
    // Returning STATUS_NOT_IMPLEMENTED in RW mode (require extent allocator
    // + variable-KV catalog insert/split, both pending):
    //  - `create` (need catalog insert + extent alloc)
    //  - `rename` (need catalog insert/remove with name hashing)
    //  - `set_file_size` / `overwrite` for grow (need alloc + dstream rewrite)
    //  - `write` past EOF or with `write_to_eof` (needs alloc)
    //  - `set_delete` for directories or hardlinked files
    // ------------------------------------------------------------------

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        let create = filetime_to_apfs_nanos(creation_time);
        let access = filetime_to_apfs_nanos(last_access_time);
        let write = filetime_to_apfs_nanos(last_write_time);
        let change = filetime_to_apfs_nanos(last_change_time);

        let mut vol = self.volume.lock().unwrap();
        vol.set_inode_times(&context.path, create, write, change, access)
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        drop(vol);

        // Invalidate cached stat so the next get_file_info reflects the change
        self.stat_cache.lock().unwrap().pop(&context.path);

        // Refill file_info from the new stat
        let mut vol = self.volume.lock().unwrap();
        if let Ok(stat) = vol.stat(&context.path) {
            let ft = |n| self.apfs_time_to_filetime(n);
            let attr = |k| self.entry_kind_to_attributes(k);
            Self::fill_file_info(file_info, &stat, stat.size, ft, attr);
        }
        Ok(())
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        if buffer.is_empty() {
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(0);
        }

        // In-place write semantics: this branch never reallocates extents
        // For writes past EOF we route through `append_data` (write_to_eof)
        // or `grow_file` + in-place rewrite (sparse middle, write past EOF)
        if write_to_eof {
            let mut vol = self.volume.lock().unwrap();
            vol.append_data(&context.path, buffer)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            drop(vol);
            self.stat_cache.lock().unwrap().pop(&context.path);
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(buffer.len() as u32);
        }

        let max_writable = context.file_size.saturating_sub(offset);
        if max_writable == 0 {
            // `constrained_io` semantics: short write of zero is success;
            // for unconstrained writes past EOF, grow the file then rewrite
            if constrained_io {
                self.refresh_file_info_after_write(context, file_info)?;
                return Ok(0);
            }
            let new_size = offset + buffer.len() as u64;
            let mut vol = self.volume.lock().unwrap();
            vol.grow_file(&context.path, new_size)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            // Re-resolve extents after grow and write through them in place
            let (_stat, extent_map, _) = vol
                .stat_and_extents(&context.path)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            vol.write_at_extents(&extent_map, offset, buffer)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            drop(vol);
            self.stat_cache.lock().unwrap().pop(&context.path);
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(buffer.len() as u32);
        }
        let to_write = (buffer.len() as u64).min(max_writable) as usize;
        if !constrained_io && to_write < buffer.len() {
            // Caller wants a full-length write but it would extend the file
            // Grow first, then write through the refreshed extents
            let new_size = offset + buffer.len() as u64;
            let mut vol = self.volume.lock().unwrap();
            vol.grow_file(&context.path, new_size)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            let (_stat, extent_map, _) = vol
                .stat_and_extents(&context.path)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            vol.write_at_extents(&extent_map, offset, buffer)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            drop(vol);
            self.stat_cache.lock().unwrap().pop(&context.path);
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(buffer.len() as u32);
        }

        let mut vol = self.volume.lock().unwrap();
        let written = vol
            .write_at_extents(&context.extent_map, offset, &buffer[..to_write])
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        drop(vol);

        // The cached stat is unchanged for size, but mtime is no longer
        // accurate without an explicit set_basic_info from the caller; the
        // OS issues that itself for typical write patterns, so we don't
        // shadow-update mtime here
        self.refresh_file_info_after_write(context, file_info)?;
        Ok(written as u32)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        if new_size == context.file_size {
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(());
        }
        if new_size > context.file_size {
            // Grow: allocate fresh blocks, zero-fill, install file_extent
            let mut vol = self.volume.lock().unwrap();
            vol.grow_file(&context.path, new_size)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            drop(vol);
            self.stat_cache.lock().unwrap().pop(&context.path);
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(());
        }
        // Shrink: splice the dstream xfield only; allocated extents leak
        let mut vol = self.volume.lock().unwrap();
        vol.set_logical_size(&context.path, new_size)
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        drop(vol);
        self.stat_cache.lock().unwrap().pop(&context.path);
        self.refresh_file_info_after_write(context, file_info)?;
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        if !delete_file {
            // Cancel pending delete; we don't track per-handle state
            // beyond what WinFSP already does, so this is a no-op accept
            return Ok(());
        }
        // Pre-validate: only regular files with nlink==1 are deletable
        // through the unlink_file path. Directories and hardlinks are not
        // yet supported. We don't perform the unlink here — it happens in
        // `cleanup` when WinFSP signals FspCleanupDelete
        let mut vol = self.volume.lock().unwrap();
        let stat = vol
            .stat(&context.path)
            .map_err(|_| FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND))?;
        drop(vol);
        if stat.kind != EntryKind::File && stat.kind != EntryKind::Directory {
            // Symlinks and other esoteric kinds aren't supported yet
            return Err(FspError::NTSTATUS(STATUS_NOT_IMPLEMENTED));
        }
        if stat.kind == EntryKind::File && stat.nlink != 1 {
            // Hardlinks need sibling-link bookkeeping that we don't have
            return Err(FspError::NTSTATUS(STATUS_NOT_IMPLEMENTED));
        }
        Ok(())
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        let from = self.u16_to_path(file_name);
        let to = self.u16_to_path(new_file_name);
        let mut vol = self.volume.lock().unwrap();
        vol.rename_file(&from, &to, replace_if_exists)
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        drop(vol);
        let mut cache = self.stat_cache.lock().unwrap();
        cache.pop(&from);
        cache.pop(&to);
        Ok(())
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[std::ffi::c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        const FILE_DIRECTORY_FILE: u32 = 0x00000001;
        let path = self.u16_to_path(file_name);
        let mut vol = self.volume.lock().unwrap();
        if create_options & FILE_DIRECTORY_FILE != 0 {
            vol.create_directory(&path)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        } else {
            vol.create_file(&path)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        }
        let (stat, extent_map, file_size) = vol
            .stat_and_extents(&path)
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        drop(vol);
        let info: &mut FileInfo = file_info.as_mut();
        let ft = |n| self.apfs_time_to_filetime(n);
        let attr = |k| self.entry_kind_to_attributes(k);
        Self::fill_file_info(info, &stat, file_size, ft, attr);
        let cached = CachedStat {
            stat,
            extent_map: extent_map.clone(),
            file_size,
            extents_resolved: true,
        };
        self.put_cached_stat(path.clone(), cached);
        Ok(ApfsFileContext {
            path,
            extent_map,
            file_size,
            dir_buffer: winfsp::filesystem::DirBuffer::new(),
        })
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return Err(FspError::NTSTATUS(STATUS_MEDIA_WRITE_PROTECTED));
        }
        if allocation_size > context.file_size {
            // Grow: allocate, zero-fill, install file_extent
            let mut vol = self.volume.lock().unwrap();
            vol.grow_file(&context.path, allocation_size)
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
            drop(vol);
            self.stat_cache.lock().unwrap().pop(&context.path);
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(());
        }
        if allocation_size == context.file_size {
            self.refresh_file_info_after_write(context, file_info)?;
            return Ok(());
        }
        let mut vol = self.volume.lock().unwrap();
        vol.set_logical_size(&context.path, allocation_size)
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        drop(vol);
        self.stat_cache.lock().unwrap().pop(&context.path);
        self.refresh_file_info_after_write(context, file_info)?;
        Ok(())
    }

    fn flush(
        &self,
        _context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // Each successful write already issues FlushFileBuffers via DiskReader;
        // metadata commits through NXSB rotation at checkpoint time
        Ok(())
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        // Only the delete bit is honoured; other cleanup flags (allocation
        // size, archive bit, time updates) are no-ops here. Errors are
        // swallowed because WinFSP's cleanup callback can't propagate them
        const FSP_CLEANUP_DELETE: u32 = 0x01;
        if self.mode != ReadWriteMode::ReadWriteUnsafe {
            return;
        }
        if flags & FSP_CLEANUP_DELETE == 0 {
            return;
        }
        let mut vol = self.volume.lock().unwrap();
        // Pick the right unlink based on the cached kind
        let kind = self
            .get_cached_stat(&context.path)
            .map(|c| c.stat.kind)
            .or_else(|| vol.stat(&context.path).ok().map(|s| s.kind));
        match kind {
            Some(EntryKind::Directory) => {
                let _ = vol.unlink_directory(&context.path);
            }
            _ => {
                let _ = vol.unlink_file(&context.path);
            }
        }
        drop(vol);
        self.stat_cache.lock().unwrap().pop(&context.path);
    }
}

// ---- WinFSP NTSTATUS constants used by the write path ----
const STATUS_MEDIA_WRITE_PROTECTED: i32 = 0xC00000A2u32 as i32;
const STATUS_NOT_IMPLEMENTED: i32 = 0xC0000002u32 as i32;
const STATUS_IO_DEVICE_ERROR: i32 = 0xC0000185u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC0000034u32 as i32;

/// Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to APFS nanoseconds
/// (since 1970-01-01). Returns `None` for 0, the sentinel meaning "do not change"
fn filetime_to_apfs_nanos(filetime: u64) -> Option<i64> {
    if filetime == 0 {
        return None;
    }
    const UNIX_EPOCH_IN_FILETIME: u64 = 116_444_736_000_000_000;
    if filetime < UNIX_EPOCH_IN_FILETIME {
        return None;
    }
    let intervals_since_unix = filetime - UNIX_EPOCH_IN_FILETIME;
    Some((intervals_since_unix as i64).saturating_mul(100))
}
