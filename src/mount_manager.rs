use crate::device_monitor::ApfsPartition;
use crate::disk::DiskReader;
use crate::driver::ApfsDriver;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::info;
use winfsp::host::{FileSystemHost, VolumeParams};

pub struct MountedVolume {
    pub partition: ApfsPartition,
    pub drive_letter: char,
    pub host: FileSystemHost<ApfsDriver>,
}

pub struct MountManager {
    mounts: Arc<Mutex<HashMap<String, MountedVolume>>>,
}

impl MountManager {
    pub fn new() -> Self {
        Self {
            mounts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn mount_partition(
        &self,
        partition: ApfsPartition,
        drive_letter: char,
    ) -> anyhow::Result<()> {
        let key = format!("{}:{}", partition.disk_number, partition.partition_number);

        let disk = DiskReader::open_with_offset(&partition.device_path, partition.offset)?;
        let driver = ApfsDriver::new(disk)?;

        let mut volume_params = VolumeParams::new();
        volume_params
            .prefix("")
            .filesystem_name("APFS")
            .case_sensitive_search(true)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .read_only_volume(true)
            .sector_size(512)
            .sectors_per_allocation_unit(1)
            .volume_serial_number(0x12345678);

        let mut host = FileSystemHost::new(volume_params, driver)?;
        let mount_point = format!(r"\\.\{}:", drive_letter);

        host.mount(&mount_point)?;
        host.start()?;

        info!(
            "Mounted APFS partition {}:{} at {}:",
            partition.disk_number, partition.partition_number, drive_letter
        );

        let volume = MountedVolume {
            partition,
            drive_letter,
            host,
        };

        self.mounts.lock().unwrap().insert(key, volume);
        Ok(())
    }

    pub fn unmount_partition(&self, disk_num: u32, partition_num: u32) -> anyhow::Result<()> {
        let key = format!("{}:{}", disk_num, partition_num);

        if let Some(volume) = self.mounts.lock().unwrap().remove(&key) {
            info!("Unmounting {}:", volume.drive_letter);
            drop(volume.host);
        }

        Ok(())
    }

    pub fn is_mounted(&self, disk_num: u32, partition_num: u32) -> bool {
        let key = format!("{}:{}", disk_num, partition_num);
        self.mounts.lock().unwrap().contains_key(&key)
    }

    pub fn get_mounted_disks(&self) -> Vec<u32> {
        self.mounts
            .lock()
            .unwrap()
            .values()
            .map(|v| v.partition.disk_number)
            .collect()
    }
}
