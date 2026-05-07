use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "ARFW";
const SERVICE_DISPLAY_NAME: &str = "APFS Read-only File System for Windows";
const SERVICE_DESCRIPTION: &str = "Automatically mounts APFS partitions as read-only drives";

define_windows_service!(ffi_service_main, service_main);

pub fn install_service() -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let exe_path = std::env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(
            &service_info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .context("Failed to create service")?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .context("Failed to set service description")?;

    println!("Service '{}' installed successfully!", SERVICE_NAME);
    println!("Starting service...");

    service
        .start::<&str>(&[])
        .context("Failed to start service")?;

    println!("Service started successfully!");
    println!("The service is configured to start automatically on system boot.");

    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("Failed to open service")?;

    let status = service.query_status()?;
    if status.current_state != ServiceState::Stopped {
        println!("Stopping service...");
        service.stop().context("Failed to stop service")?;

        std::thread::sleep(Duration::from_secs(2));
    }

    service.delete().context("Failed to delete service")?;
    println!("Service '{}' uninstalled successfully!", SERVICE_NAME);

    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("Service error: {}", e);
    }
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    crate::run_daemon_internal(shutdown_rx)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

pub fn run_service_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start service dispatcher")?;
    Ok(())
}
