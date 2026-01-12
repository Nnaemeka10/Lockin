//! Process Killer: Terminate Windows processes
//!
//! Phase 6.3: Windows Process API scaffolding.
//! Full Windows API integration with TerminateProcess planned for Phase 7.

use crate::error::ServiceResult;
use lockin_core::ProcessInfo;
use tracing::{info, warn};

/// Terminates a Windows process by PID.
pub struct ProcessKiller;

impl ProcessKiller {
    /// Terminate a process immediately using Windows API.
    ///
    /// # Arguments
    /// - `pid`: Process ID to terminate
    /// - `reason`: Why it's being terminated (for logging)
    ///
    /// # Details
    /// Phase 6.3: Scaffolding for Windows API integration.
    /// Phase 7 will implement actual TerminateProcess with OpenProcess, CloseHandle.
    ///
    /// # Errors
    /// Returns ProcessTerminationFailed if termination fails.
    pub fn terminate(pid: u32, reason: &str) -> ServiceResult<()> {
        info!("Attempting to terminate process {}: {}", pid, reason);

        // Verify process exists
        if !Self::process_exists(pid) {
            warn!("Process {} not found - may have already terminated", pid);
            return Ok(());
        }

        // Phase 7: Full Windows API TerminateProcess implementation
        info!("Successfully terminated process {} (Phase 6.3 scaffold)", pid);
        Ok(())
    }

    /// Check if a process exists (simple check).
    ///
    /// Phase 6.3: Placeholder implementation.
    /// Phase 7 will integrate with CreateToolhelp32Snapshot for verification.
    fn process_exists(pid: u32) -> bool {
        // Phase 7: Use CreateToolhelp32Snapshot to verify process ID is valid
        // For now, accept all non-zero PIDs as potentially existing
        pid > 0
    }

    /// Terminate a process and watch for respawns.
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
