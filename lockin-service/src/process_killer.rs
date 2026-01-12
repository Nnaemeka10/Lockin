//! Process Killer: Terminate Windows processes

use crate::error::ServiceResult;
use lockin_core::ProcessInfo;
use tracing::{info, warn};

/// Terminates a Windows process by PID.
///
/// Phase 6: Mock implementation (returns success).
/// Phase 6.1: Integrate Windows API (TerminateProcess).
pub struct ProcessKiller;

impl ProcessKiller {
    /// Terminate a process immediately.
    ///
    /// # Arguments
    /// - `pid`: Process ID to terminate
    /// - `reason`: Why it's being terminated (for logging)
    pub fn terminate(pid: u32, reason: &str) -> ServiceResult<()> {
        // Phase 6: Mock - just log
        info!("Process {}: {}", pid, reason);

        // Phase 6.1: Will implement with Windows API:
        // OpenProcess(PROCESS_TERMINATE, false, pid)
        // TerminateProcess(handle, 1)
        // CloseHandle(handle)

        Ok(())
    }

    /// Terminate a process and any respawns.
    pub fn terminate_with_respawn_detection(
        process: &ProcessInfo,
        reason: &str,
    ) -> ServiceResult<()> {
        Self::terminate(process.pid, reason)?;
        warn!(
            "Terminated {} (PID {}) - watching for respawns",
            process.exe_name,
            process.pid
        );
        Ok(())
    }
}
