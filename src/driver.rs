use crate::disk::DiskReader;
use crate::error::{Error, Result};
use apfs::{ApfsVolume, EntryKind, FileStat};
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

/// Cached metadata for a path — stored in the LRU cache.
#[derive(Clone)]
struct CachedStat {
    stat: FileStat,
    /// Extent map for files; empty for directories.
    extent_map: Vec<ExtentEntry>,
    /// Logical file size; 0 for directories.
    file_size: u64,
    /// True when extent_map was resolved via stat_and_extents().
    /// False when populated from list_directory() — extent_map is empty in that case.
    extents_resolved: bool,
}

/// Capacity of the path stat cache.
/// 4096 entries covers typical directory listings without excessive memory use.
const STAT_CACHE_CAPACITY: usize = 4096;

pub struct ApfsDriver {
    /// Used exclusively for metadata operations (stat, list_directory, open).
    /// Protected by Mutex because ApfsVolume uses sequential Read+Seek internally.
    volume: Arc<Mutex<ApfsVolume<DiskReader>>>,
    /// Second independent handle to the same device for raw positioned reads.
    /// No Mutex needed: Windows HANDLE + OVERLAPPED I/O is thread-safe.
    raw_disk: Arc<DiskReader>,
    disk_size: u64,
    /// LRU cache: path -> CachedStat.
    /// Eliminates repeated B-tree traversals for the same path.
    /// Protected by its own Mutex so reads don't block on `volume`.
    stat_cache: Mutex<LruCache<String, CachedStat>>,
}

pub struct ApfsFileContext {
    path: String,
    /// Extent map resolved once at open() time.
    extent_map: Vec<ExtentEntry>,
    /// Logical file size in bytes.
    file_size: u64,
    dir_buffer: winfsp::filesystem::DirBuffer,
}

impl ApfsDriver {
    pub fn new(disk: DiskReader) -> Result<Self> {
        let raw_disk = disk.reopen()?;

        let mut meta_disk = disk.reopen()?;
        let disk_size = meta_disk
            .read_apfs_container_size()
            .unwrap_or_else(|_| disk.size());

        let volume = ApfsVolume::open(disk).map_err(|e| Error::Apfs(e.to_string()))?;

        Ok(Self {
            volume: Arc::new(Mutex::new(volume)),
            raw_disk: Arc::new(raw_disk),
            disk_size,
            stat_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(STAT_CACHE_CAPACITY).unwrap(),
            )),
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

    /// Look up a path: check cache first, fall back to B-tree traversal.
    fn get_cached_stat(&self, path: &str) -> Option<CachedStat> {
        self.stat_cache.lock().unwrap().get(path).cloned()
    }

    /// Store a stat result in the cache.
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

        // Fast path: root is always a directory.
        if path == "/" || path.is_empty() {
            return Ok(FileSecurity {
                reparse: false,
                sz_security_descriptor: 0,
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
            });
        }

        // Check cache first — avoids B-tree traversal on repeated lookups.
        if let Some(cached) = self.get_cached_stat(&path) {
            return Ok(FileSecurity {
                reparse: false,
                sz_security_descriptor: 0,
                attributes: self.entry_kind_to_attributes(cached.stat.kind),
            });
        }

        // Cache miss: do the B-tree traversal and populate cache.
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

        // get_security_by_name is always called before open() by WinFSP,
        // so the cache should already be warm. This avoids a second B-tree traversal.
        // IMPORTANT: if the cached entry has extents_resolved=false (populated from
        // list_directory), we must still resolve the extent map before returning.
        let cached = match self.get_cached_stat(&path) {
            Some(c) if c.extents_resolved || c.stat.kind == EntryKind::Directory => c,
            _ => {
                // Either cache miss or stat-only entry — resolve full stat+extents.
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

            let bytes = self
                .raw_disk
                .read_at(
                    physical_pos,
                    &mut buffer[total_read..total_read + chunk_size],
                )
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

        // Pre-populate the stat cache with all directory entries.
        // When WinFSP subsequently calls get_security_by_name + open for each
        // child, those calls will hit the cache instead of doing B-tree lookups.
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

                // Only insert if not already cached (don't evict fresher entries).
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
                    // Extent map is not available from list_directory — it will be
                    // resolved lazily on first open() if cache miss on extents.
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
        // Check cache first.
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

        out_volume_info.total_size = self.disk_size;
        out_volume_info.free_size = 0;
        out_volume_info.set_volume_label(&info.name);

        Ok(())
    }
}
