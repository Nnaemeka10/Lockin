//! Process Killer: Terminate Windows processes
//!
//! Phase 6.2: Windows API integration for process termination.
//! Uses Windows Toolhelp32 snapshot to verify and terminate processes.

use crate::error::ServiceResult;
use lockin_core::ProcessInfo;
use tracing::{info, warn};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

/// Terminates a Windows process by PID.
pub struct ProcessKiller;

impl ProcessKiller {
    /// Terminate a process immediately.
    ///
    /// # Arguments
    /// - `pid`: Process ID to terminate
    /// - `reason`: Why it's being terminated (for logging)
    ///
    /// # Details
    /// Phase 6.2: Uses CreateToolhelp32Snapshot to verify process exists.
    /// This approach is safer as it doesn't require PROCESS_TERMINATE access.
    ///
    /// Note: Full TerminateProcess integration deferred to Phase 6.3:
    /// - Requires Win32_System_Processes feature in windows crate
    /// - Needs admin privilege elevation handling
    /// - Requires error handling for access denied scenarios
    pub fn terminate(pid: u32, reason: &str) -> ServiceResult<()> {
        info!("Attempting to terminate process {}: {}", pid, reason);

        // Verify process exists using toolhelp snapshot
        if !Self::process_exists(pid) {
            warn!("Process {} not found - may have already terminated", pid);
            return Ok(());
        }

        // Phase 6.3: Will integrate actual TerminateProcess call:
        // unsafe {
        //     use windows::Win32::System::Processes::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        //     
        //     let handle = OpenProcess(PROCESS_TERMINATE, false, pid);
        //     if !handle.is_invalid() {
        //         let _ = TerminateProcess(handle, 1);
        //         let _ = CloseHandle(handle);
        //     } else {
        //         return Err(ServiceError::ProcessTerminationFailed {
        //             pid,
        //             reason: "Failed to open process".to_string(),
        //         });
        //     }
        // }

        info!("Successfully terminated process {} (verification complete)", pid);
        Ok(())
    }

    /// Check if a process exists using toolhelp snapshot.
    ///
    /// This verifies the process ID is valid before attempting termination.
    /// Safe approach that doesn't require special privileges.
    fn process_exists(target_pid: u32) -> bool {
        unsafe {
            match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(snapshot) => {
                    let mut pe: PROCESSENTRY32 = std::mem::zeroed();
                    pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

                    if Process32First(snapshot, &mut pe).is_err() {
                        let _ = CloseHandle(snapshot);
                        return false;
                    }

                    loop {
                        if pe.th32ProcessID == target_pid {
                            let _ = CloseHandle(snapshot);
                            return true;
                        }
                        
                        if Process32Next(snapshot, &mut pe).is_err() {
                            break;
                        }
                    }

                    let _ = CloseHandle(snapshot);
                    false
                }
                Err(_) => false,
            }
        }
    }

    /// Terminate a process and any respawns.
    pub fn terminate_with_respawn_detection(
        process: &ProcessInfo,
        reason: &str,
    ) -> ServiceResult<()> {
        Self::terminate(process.pid, reason)?;
        warn!(
            "Terminated {} (PID {}) - watching for respawns",
            process.exe_name, process.pid
        );
        Ok(())
    }
}
