//! IPC: Inter-Process Communication with UI
//!
//! Phase 6: Skeleton only (no actual IPC channel).
//! Phase 7: Will implement with named pipes, sockets, or other mechanism.

use crate::error::{ServiceError, ServiceResult};
use serde::{Deserialize, Serialize};

/// Command from UI to service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcCommand {
    /// Create a new lock.
    CreateLock {
        app_name: String,
        duration_days: i64,
    },

    /// Query current lock status.
    QueryStatus,

    /// Stop the service.
    Stop,
}

/// Response from service to UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Lock was created successfully.
    LockCreated { lock_id: String },

    /// Current status.
    Status { active_locks: usize },

    /// Error response.
    Error { message: String },
}

/// IPC Channel (skeleton for Phase 7).
pub struct IpcChannel;

impl IpcChannel {
    /// Create a new IPC channel (Phase 7 implementation).
    pub fn new() -> ServiceResult<Self> {
        // Phase 7: Will implement with named pipes:
        // CreateNamedPipeA("\\.\pipe\Lockin", ...)
        Ok(IpcChannel)
    }

    /// Listen for incoming commands (Phase 7 implementation).
    pub async fn listen(&self) -> ServiceResult<IpcCommand> {
        // Phase 7: Will implement channel reading
        Err(ServiceError::IpcError(
            "IPC listening not yet implemented (Phase 7)".to_string(),
        ))
    }

    /// Send a response to UI (Phase 7 implementation).
    pub async fn send_response(&self, response: IpcResponse) -> ServiceResult<()> {
        log::debug!("IPC response (mock): {:?}", response);
        // Phase 7: Will implement channel writing
        Ok(())
    }

    /// Broadcast warning to UI (connected clients).
    pub async fn broadcast_warning(&self, app_name: &str, time_remaining_ms: u64) -> ServiceResult<()> {
        log::info!(
            "UI Warning: {} will close in {}ms",
            app_name,
            time_remaining_ms
        );
        Ok(())
    }
}

impl Default for IpcChannel {
    fn default() -> Self {
        IpcChannel
    }
}
