#[cfg(not(windows))]
fn main() {
    eprintln!("arfw bin only supported on Windows; the apfs library compiles cross-platform.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> { windows_main::main() }

#[cfg(windows)]
mod service;

#[cfg(windows)]
fn run_daemon_internal(shutdown_rx: std::sync::mpsc::Receiver<()>) -> anyhow::Result<()> {
    windows_main::run_daemon_internal(shutdown_rx)
}

#[cfg(windows)]
mod windows_main {
    use arfw::device_monitor::DeviceMonitor;
    use arfw::device_watcher::{DeviceEvent, DeviceWatcher};
    use arfw::disk::DiskReader;
    use arfw::driver::{self, ApfsDriver};
    use arfw::mount_manager::MountManager;
    use clap::Parser;
    use std::collections::HashSet;
    use tracing::info;
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::SetDllDirectoryW;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    use winfsp::host::{FileSystemHost, VolumeParams};
    use crate::service;
    
    #[derive(Parser, Debug)]
    #[command(name = "arfw")]
    #[command(about = "APFS filesystem read only support for Windows", long_about = None)]
    struct Args {
        #[command(subcommand)]
        command: Option<Command>,
    }
    
    #[derive(Parser, Debug)]
    enum Command {
        /// Mount a specific device manually
        Mount {
            /// Physical drive path (e.g., \\.\PhysicalDrive1)
            #[arg(value_name = "DEVICE")]
            device: String,
    
            /// Mount point (e.g., X:)
            #[arg(short = 'm', long = "mount", value_name = "MOUNTPOINT")]
            mount_point: String,
    
            /// Volume index (default: 0)
            #[arg(short = 'v', long = "volume", default_value = "0")]
            volume_index: usize,
    
            /// Enable debug logging
            #[arg(short = 'd', long = "debug")]
            debug: bool,
    
            /// EXPERIMENTAL: open the volume read/write. Currently a no-op for
            /// I/O paths (write callbacks are not yet wired through WinFSP);
            /// reserved for the in-progress write support. Requires the env
            /// var `ARFW_I_UNDERSTAND_DATA_LOSS=1` to be set. Loopback / disk
            /// images only; never use against a physical disk you care about
            #[arg(long = "rw-unsafe", default_value_t = false)]
            rw_unsafe: bool,
        },
        /// Run as daemon - auto-mount all APFS drives
        Daemon {
            /// Enable debug logging
            #[arg(short = 'd', long = "debug")]
            debug: bool,
        },
        /// Install as Windows service (requires admin privileges)
        Install,
        /// Uninstall Windows service (requires admin privileges)
        Uninstall,
        #[command(hide = true)]
        Service,
    }
    
    fn setup_winfsp_dll_path() -> anyhow::Result<()> {
        let mut path = [0u16; 260];
        let mut size = (path.len() * std::mem::size_of::<u16>()) as u32;
    
        // SAFETY: `path` is a fixed-size stack buffer [0u16; 260]. `size` is
        // initialised to the buffer's byte length so RegGetValueW will not write
        // beyond it. The type-erased `*mut _` cast is the standard pattern for
        // registry API output buffers
        // `wide` is a null-terminated UTF-16 Vec<u16> that outlives the
        // synchronous SetDllDirectoryW call; the function does not retain the
        // pointer after returning
        unsafe {
            let result = RegGetValueW(
                HKEY_LOCAL_MACHINE,
                windows::core::w!("SOFTWARE\\WOW6432Node\\WinFsp"),
                windows::core::w!("InstallDir"),
                RRF_RT_REG_SZ,
                None,
                Some(path.as_mut_ptr() as *mut _),
                Some(&mut size),
            );
    
            if result.is_err() {
                anyhow::bail!("Failed to read WinFsp registry key");
            }
    
            let len = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            let mut bin_path = String::from_utf16_lossy(&path[..len]);
            bin_path.push_str("\\bin");
    
            let wide: Vec<u16> = bin_path.encode_utf16().chain(std::iter::once(0)).collect();
            SetDllDirectoryW(PCWSTR(wide.as_ptr()))?;
        }
    
        Ok(())
    }
    
    fn run_manual_mount(
        device: String,
        mount_point: String,
        _volume_index: usize,
        debug: bool,
        rw_unsafe: bool,
    ) -> anyhow::Result<()> {
        let level = if debug { "debug" } else { "info" };
        tracing_subscriber::fmt().with_env_filter(level).init();
    
        info!("ARFW v{}", env!("CARGO_PKG_VERSION"));
        info!("Opening device: {}", device);
    
        let partition_offset = 1048576;
        let disk = DiskReader::open_with_offset(&device, partition_offset)?;
        info!("Disk opened successfully with offset {}", partition_offset);
    
        let mode = if rw_unsafe {
            tracing::warn!(
                "--rw-unsafe specified: opening volume in EXPERIMENTAL read/write mode. \
                 Only timestamp updates (set_basic_info) are functional today; data \
                 writes / create / rename / delete return STATUS_NOT_IMPLEMENTED. \
                 USE A DISK-IMAGE TARGET ONLY."
            );
            driver::ReadWriteMode::ReadWriteUnsafe
        } else {
            driver::ReadWriteMode::ReadOnly
        };
        let driver = ApfsDriver::with_mode(disk, mode)?;
        info!("APFS volume loaded");
    
        let mut volume_params = VolumeParams::new();
        volume_params
            .prefix("")
            .filesystem_name("APFS")
            .case_sensitive_search(true)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .read_only_volume(mode == driver::ReadWriteMode::ReadOnly)
            .sector_size(512)
            .sectors_per_allocation_unit(1)
            .volume_serial_number(0x12345678);
    
        let mut host = FileSystemHost::new(volume_params, driver)?;
        info!("FileSystemHost created");
    
        let mount_point = if mount_point.len() == 2 && mount_point.ends_with(':') {
            format!(r"\\.\{}", mount_point)
        } else {
            mount_point.clone()
        };
    
        host.mount(&mount_point)?;
        info!("Mounted at {} (global drive)", mount_point);
    
        host.start()?;
        info!("Dispatcher started. Filesystem is now accessible.");
        info!("Press Ctrl+C to unmount and exit.");
    
        let (tx, rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || {
            tx.send(()).expect("Could not send signal");
        })?;
    
        rx.recv()?;
        info!("Unmounting...");
    
        drop(host);
        info!("Unmounted successfully");
    
        Ok(())
    }
    
    fn run_daemon(debug: bool) -> anyhow::Result<()> {
        let level = if debug { "debug" } else { "info" };
        tracing_subscriber::fmt().with_env_filter(level).init();
    
        let (signal_tx, signal_rx) = std::sync::mpsc::channel();
    
        ctrlc::set_handler(move || {
            let _ = signal_tx.send(());
        })?;
    
        run_daemon_internal(signal_rx)
    }
    
    pub fn run_daemon_internal(shutdown_rx: std::sync::mpsc::Receiver<()>) -> anyhow::Result<()> {
        info!("ARFW Daemon v{}", env!("CARGO_PKG_VERSION"));
        info!("Starting APFS daemon...");
    
        let manager = MountManager::new();
        let mut known_partitions = HashSet::new();
    
        let (device_tx, device_rx) = crossbeam_channel::unbounded();
    
        let _watcher = DeviceWatcher::new(device_tx)?;
        info!("Device watcher active. Waiting for disk events...");
    
        scan_and_update(&manager, &mut known_partitions);
    
        loop {
            crossbeam_channel::select! {
                recv(device_rx) -> event => {
                    match event {
                        Ok(DeviceEvent::Added) => {
                            info!("Device added event received");
                            scan_and_update(&manager, &mut known_partitions);
                        }
                        Ok(DeviceEvent::Removed) => {
                            info!("Device removed event received");
                            scan_and_update(&manager, &mut known_partitions);
                        }
                        Err(_) => break,
                    }
                }
                default(std::time::Duration::from_millis(100)) => {
                    if shutdown_rx.try_recv().is_ok() {
                        info!("Shutting down daemon...");
                        break;
                    }
                }
            }
        }
    
        Ok(())
    }
    
    fn scan_and_update(manager: &MountManager, known_partitions: &mut HashSet<(u32, u32)>) {
        match DeviceMonitor::scan_apfs_partitions() {
            Ok(partitions) => {
                let current_partitions: HashSet<_> = partitions
                    .iter()
                    .map(|p| (p.disk_number, p.partition_number))
                    .collect();
    
                // Mount new partitions
                for partition in &partitions {
                    let key = (partition.disk_number, partition.partition_number);
                    if !known_partitions.contains(&key) {
                        if let Some(drive_letter) =
                            DeviceMonitor::find_available_drive_letters().first()
                        {
                            match manager.mount_partition(partition.clone(), *drive_letter) {
                                Ok(_) => {
                                    known_partitions.insert(key);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to mount partition {:?}: {}", key, e);
                                }
                            }
                        }
                    }
                }
    
                // Unmount removed partitions
                let removed: Vec<_> = known_partitions
                    .difference(&current_partitions)
                    .cloned()
                    .collect();
                for (disk_num, partition_num) in removed {
                    let _ = manager.unmount_partition(disk_num, partition_num);
                    known_partitions.remove(&(disk_num, partition_num));
                }
            }
            Err(e) => {
                tracing::error!("Failed to scan partitions: {}", e);
            }
        }
    }
    
    pub fn main() -> anyhow::Result<()> {
        setup_winfsp_dll_path()?;
    
        let args = Args::parse();
    
        // For the Service command, WinFsp initialization is handled inside run_service()
        // with a retry loop; WinFsp may not be available yet at service startup time
        // For all other commands, initialize immediately and die on failure
        let _fsp = match args.command {
            Some(Command::Service) => None,
            _ => Some(winfsp::winfsp_init_or_die()),
        };
    
        match args.command {
            Some(Command::Mount {
                device,
                mount_point,
                volume_index,
                debug,
                rw_unsafe,
            }) => run_manual_mount(device, mount_point, volume_index, debug, rw_unsafe),
            Some(Command::Daemon { debug }) => run_daemon(debug),
            Some(Command::Install) => service::install_service(),
            Some(Command::Uninstall) => service::uninstall_service(),
            Some(Command::Service) => {
                tracing_subscriber::fmt().with_env_filter("info").init();
                service::run_service_dispatcher()
            }
            None => run_daemon(false),
        }
    }
}
