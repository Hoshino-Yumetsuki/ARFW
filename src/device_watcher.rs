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
    /// Owning pointer to the Sender passed as context to the OS callback
    /// Must be freed after CM_Unregister_Notification returns (which guarantees
    /// no in-flight callbacks remain that could still dereference this pointer)
    sender_ptr: *mut Sender<DeviceEvent>,
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

        // SAFETY: `sender_ptr` is a valid heap-allocated Sender<DeviceEvent>
        // created by Box::into_raw above. The pointer is stored in `self` and
        // freed in Drop after CM_Unregister_Notification returns, which
        // guarantees all in-flight callbacks have completed before the pointer
        // is released. The callback validates the pointer is non-null before
        // dereferencing it
        let result = unsafe {
            CM_Register_Notification(
                &filter,
                Some(sender_ptr as *const c_void),
                Some(Self::callback),
                &mut handle,
            )
        };

        if result != CR_SUCCESS {
            // Registration failed — reclaim the Box to avoid a leak
            // SAFETY: `sender_ptr` was created by Box::into_raw above and has
            // not been passed to any OS callback yet (registration failed)
            unsafe { drop(Box::from_raw(sender_ptr)) };
            anyhow::bail!("Failed to register device notification: {:?}", result);
        }

        info!("Device watcher registered for disk notifications");
        Ok(Self { handle, sender_ptr })
    }

    // SAFETY: This function is called by the Windows CM notification subsystem
    // `context` is the `sender_ptr` passed to CM_Register_Notification — a
    // valid `*mut Sender<DeviceEvent>` heap-allocated in `new()`. The OS
    // guarantees this callback is not invoked after CM_Unregister_Notification
    // returns, so the pointer is always valid when this function runs
    // We only take a shared reference (`&*`) and never move or free the value
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

        // SAFETY: `context` is a valid `*const Sender<DeviceEvent>` for the
        // lifetime of this callback (see function-level SAFETY comment above)
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
        // SAFETY: CM_Unregister_Notification blocks until all in-flight
        // callbacks have completed before returning. After this call returns,
        // no callback can dereference `sender_ptr`, so it is safe to free it
        unsafe {
            let _ = CM_Unregister_Notification(self.handle);
        }
        info!("Device watcher unregistered");

        // Reclaim the Box to free the Sender memory
        // SAFETY: `sender_ptr` was created by Box::into_raw in `new()` and has
        // not been freed yet. CM_Unregister_Notification above guarantees no
        // callback is running or will run after this point
        unsafe {
            drop(Box::from_raw(self.sender_ptr));
        }
    }
}
