use anyhow::Result;
use std::process::Command;
use tracing::{info, warn};

#[cfg(windows)]
#[link(name = "winmm")]
extern "system" {
    fn timeBeginPeriod(uPeriod: u32) -> u32;
    fn timeEndPeriod(uPeriod: u32) -> u32;
}

#[cfg(windows)]
#[link(name = "avrt")]
extern "system" {
    fn AvSetMmThreadCharacteristicsW(TaskName: *const u16, TaskIndex: *mut u32) -> *mut std::ffi::c_void;
    fn AvRevertMmThreadCharacteristics(AvrtHandle: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentThread() -> *mut std::ffi::c_void;
    fn SetThreadPriority(hThread: *mut std::ffi::c_void, nPriority: i32) -> i32;
}

// Windows thread priority constants
const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
const THREAD_PRIORITY_HIGHEST: i32 = 2;

/// Manages Windows OS and network tuning for competitive gaming performance.
pub struct WindowsGamingTuner;

impl WindowsGamingTuner {
    /// Applies real-time OS optimizations for virtual LAN gaming:
    /// 1. Locks Windows timer resolution to 1.0ms (default is 15.625ms).
    /// 2. Configures a Windows NetQoS policy for DSCP Expedited Forwarding (EF = 46).
    pub fn apply_system_optimizations(app_name: &str) -> Result<()> {
        info!("Applying Windows OS Gaming optimizations for '{}'...", app_name);

        #[cfg(windows)]
        unsafe {
            // Lock system timer resolution to 1ms
            let res = timeBeginPeriod(1);
            if res != 0 {
                warn!("timeBeginPeriod(1) returned code: {}", res);
            } else {
                info!("Locked Windows system timer resolution to 1.0ms");
            }
        }

        // Apply NetQoS policy for DSCP 46 (Expedited Forwarding / WMM Voice)
        Self::apply_dscp_qos_policy(app_name);

        Ok(())
    }

    /// Register the current thread with Windows Multimedia Class Scheduler Service (MMCSS)
    /// under the "Games" profile and set thread priority to TIME_CRITICAL.
    #[cfg(windows)]
    pub fn tune_worker_thread(thread_name: &str) {
        unsafe {
            let mut task_index = 0u32;
            let task_name: Vec<u16> = "Games\0".encode_utf16().collect();
            let mmcss_handle = AvSetMmThreadCharacteristicsW(task_name.as_ptr(), &mut task_index);
            if !mmcss_handle.is_null() {
                info!("Registered '{}' with Windows MMCSS ('Games' class)", thread_name);
            } else {
                warn!("Could not register '{}' with MMCSS, falling back to priority boost", thread_name);
            }

            let thread_handle = GetCurrentThread();
            let res = SetThreadPriority(thread_handle, THREAD_PRIORITY_TIME_CRITICAL);
            if res != 0 {
                info!("Elevated thread '{}' priority to TIME_CRITICAL", thread_name);
            } else {
                SetThreadPriority(thread_handle, THREAD_PRIORITY_HIGHEST);
            }
        }
    }

    #[cfg(not(windows))]
    pub fn tune_worker_thread(_thread_name: &str) {}

    /// Configures Windows NetQoS policy for DSCP Expedited Forwarding (EF = 46)
    fn apply_dscp_qos_policy(app_name: &str) {
        let ps_bin = crate::network::tunnel::resolve_powershell_path();

        let ps_cmd = format!(
            "if (-not (Get-NetQosPolicy -Name 'ElysiumGamingQoS' -ErrorAction SilentlyContinue)) {{ \
                New-NetQosPolicy -Name 'ElysiumGamingQoS' -AppPathNameMatchCondition '{}' \
                -IPProtocolMatchCondition UDP -DSCPAction 46 -NetworkProfile All -Confirm:$false | Out-Null \
            }}",
            app_name
        );

        let status = Command::new(&ps_bin)
            .args(&["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
            .status();

        match status {
            Ok(s) if s.success() => info!("Configured NetQoS policy: DSCP 46 (Expedited Forwarding) for UDP"),
            Ok(s) => warn!("NetQoS command exited with code {:?}", s.code()),
            Err(e) => warn!("Could not apply NetQoS policy: {}", e),
        }
    }

    /// Teardown optimizations on app exit
    pub fn cleanup() {
        #[cfg(windows)]
        unsafe {
            let _ = timeEndPeriod(1);
        }
        info!("Cleaned up Windows system timer resolution");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_period_api() {
        #[cfg(windows)]
        unsafe {
            assert_eq!(timeBeginPeriod(1), 0);
            assert_eq!(timeEndPeriod(1), 0);
        }
    }
}
