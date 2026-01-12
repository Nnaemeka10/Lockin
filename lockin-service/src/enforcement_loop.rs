//! Enforcement Loop: Main service event loop
//!
//! Periodically:
//! 1. Query for processes matching locked apps
//! 2. Get enforcement decision from engine
//! 3. Execute action (warn, terminate, wait)
//! 4. Check for respawns

use crate::error::ServiceResult;
use crate::ipc::IpcChannel;
use crate::process_killer::ProcessKiller;
use lockin_core::{EnforcementAction, EnforcementEngine, ProcessQuery};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Main enforcement loop.
pub struct EnforcementLoop {
    /// Enforcement engine (contains lock state and decision logic).
    engine: EnforcementEngine,

    /// IPC channel (for UI communication).
    ipc: IpcChannel,
}

impl EnforcementLoop {
    /// Create a new enforcement loop.
    pub fn new(engine: EnforcementEngine) -> ServiceResult<Self> {
        let ipc = IpcChannel::new()?;

        Ok(EnforcementLoop { engine, ipc })
    }

    /// Run the enforcement loop (blocks until shutdown).
    pub async fn run(&mut self) -> ServiceResult<()> {
        info!("Starting enforcement loop");

        let target_app = self.engine.lock_state().rule().app_name().to_string();

        loop {
            // Check if lock is still active
            if !self.engine.should_continue() {
                info!("Lock no longer active, stopping enforcement");
                break;
            }

            // Poll for locked processes
            match ProcessQuery::find_matching(&target_app) {
                Ok(processes) => {
                    for process in processes {
                        match self.engine.check_process(&process) {
                            Ok(action) => {
                                self.execute_action(&process, action).await?;
                            }
                            Err(e) => {
                                error!("Enforcement decision failed: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Process query failed: {}", e);
                }
            }

            // Sleep before next poll (100ms)
            sleep(Duration::from_millis(100)).await;
        }

        info!("Enforcement loop ended");
        Ok(())
    }

    /// Execute an enforcement action.
    async fn execute_action(
        &self,
        process: &lockin_core::ProcessInfo,
        action: EnforcementAction,
    ) -> ServiceResult<()> {
        match action {
            EnforcementAction::Ignore => {
                // Do nothing
            }

            EnforcementAction::Warn { time_remaining_ms } => {
                log::debug!(
                    "Warning: {} will close in {}ms",
                    process.exe_name,
                    time_remaining_ms
                );
                // Send to UI
                self.ipc
                    .broadcast_warning(&process.exe_name, time_remaining_ms)
                    .await?;
            }

            EnforcementAction::Terminate => {
                warn!("Terminating: {}", process.exe_name);
                ProcessKiller::terminate(process.pid, "Enforcement action")?;
            }

            EnforcementAction::WaitForRespawn => {
                debug!("Waiting for respawn check: {}", process.exe_name);
                sleep(Duration::from_millis(500)).await;
            }
        }

        Ok(())
    }
}
