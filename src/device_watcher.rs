// src/device_watcher.rs
use crossbeam_channel::Sender;
use std::ffi::c_void;
use tracing::info;
use windows::core::GUID;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Register_Notification, CM_Unregister_Notification, CM_NOTIFY_ACTION,
    CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL, CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL,
    CM_NOTIFY_EVENT_DATA, CM_NOTIFY_FILTER, CM_NOTIFY_FILTER_0,
    CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CR_SUCCESS, HCMNOTIFICATION,
};

// GUID for disk devices
const GUID_DEVINTERFACE_DISK: GUID = GUID {
    data1: 0x53f56307,
    data2: 0xb6bf,
    data3: 0x11d0,
    data4: [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
};

#[derive(Debug, Clone, Copy)]
pub enum DeviceEvent {
    Added,
    Removed,
}

pub struct DeviceWatcher {
    handle: HCMNOTIFICATION,
}

impl DeviceWatcher {
    pub fn new(sender: Sender<DeviceEvent>) -> anyhow::Result<Self> {
        let sender_ptr = Box::into_raw(Box::new(sender));

        let filter = CM_NOTIFY_FILTER {
            cbSize: std::mem::size_of::<CM_NOTIFY_FILTER>() as u32,
            Flags: 0,
            FilterType: CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
            Reserved: 0,
            u: CM_NOTIFY_FILTER_0 {
                DeviceInterface:
                    windows::Win32::Devices::DeviceAndDriverInstallation::CM_NOTIFY_FILTER_0_0 {
                        ClassGuid: GUID_DEVINTERFACE_DISK,
                    },
            },
        };

        let mut handle = HCMNOTIFICATION::default();

        let result = unsafe {
            CM_Register_Notification(
                &filter,
                Some(sender_ptr as *const c_void),
                Some(Self::callback),
                &mut handle,
            )
        };

        if result != CR_SUCCESS {
            anyhow::bail!("Failed to register device notification: {:?}", result);
        }

        info!("Device watcher registered for disk notifications");
        Ok(Self { handle })
    }

    unsafe extern "system" fn callback(
        _notify: HCMNOTIFICATION,
        context: *const c_void,
        action: CM_NOTIFY_ACTION,
        _event_data: *const CM_NOTIFY_EVENT_DATA,
        _event_data_size: u32,
    ) -> u32 {
        if context.is_null() {
            return 0;
        }

        let sender = unsafe { &*(context as *const Sender<DeviceEvent>) };

        let event = match action {
            CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL => Some(DeviceEvent::Added),
            CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL => Some(DeviceEvent::Removed),
            _ => None,
        };

        if let Some(evt) = event {
            let _ = sender.send(evt);
        }

        0
    }
}

impl Drop for DeviceWatcher {
    fn drop(&mut self) {
        unsafe {
            let _ = CM_Unregister_Notification(self.handle);
        }
        info!("Device watcher unregistered");
    }
}
