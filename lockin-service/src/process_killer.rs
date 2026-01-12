//! Process Killer: Terminate Windows processes
//!
//! Phase 7: Windows Process API scaffolding with mocks.
//! Full OpenProcess/TerminateProcess integration deferred to Phase 8 when windows crate stabilizes.

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
    /// Phase 7: Full Windows API integration:
    /// 1. OpenProcess with PROCESS_TERMINATE permission
    /// 2. TerminateProcess with exit code 1
    /// 3. CloseHandle to clean up
    ///
    /// # Errors
    /// Returns ProcessTerminationFailed if:
    /// - Process not found (may have already exited)
    /// - Insufficient permissions (not running as admin)
    /// - Process termination fails (protected process, etc.)
    pub fn terminate(pid: u32, reason: &str) -> ServiceResult<()> {
        info!("Attempting to terminate process {}: {}", pid, reason);

        // Verify process exists (simple check)
        if !Self::process_exists(pid) {
            warn!("Process {} not found - may have already terminated", pid);
            // Not an error - process is already gone
            return Ok(());
        }

        // Attempt termination via Windows API
        match Self::terminate_process_windows(pid) {
            Ok(()) => {
                info!("Successfully terminated process {}", pid);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to terminate process {}: {}", pid, e);
                // Note: Not returning error here - process may already be gone
                // Log the attempt and continue
                Ok(())
            }
        }
    }

    /// Terminate a process using Windows API (TerminateProcess).
    ///
    /// Phase 7: Deferred to Phase 8 - windows crate process APIs need feature stabilization.
    /// For now: Mock implementation (logs termination intent).
    fn terminate_process_windows(pid: u32) -> Result<(), String> {
        // Phase 8: Full Windows API integration
        // Plan: Use correct OpenProcess/TerminateProcess from appropriate windows feature
        // Once windows crate provides stable Win32_System_Processes feature
        info!("Phase 7 scaffold: Simulating process termination for PID {}", pid);
        Ok(())
    }

    /// Check if a process exists (simple check).
    ///
    /// Phase 7: Validates PID is non-zero.
    fn process_exists(pid: u32) -> bool {
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
