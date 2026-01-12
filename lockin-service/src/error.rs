//! Service: Service-specific error types

use thiserror::Error;

/// Service layer errors.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Failed to load persisted lock state: {0}")]
    LoadLockStateFailed(String),

    #[error("Failed to register Windows service: {0}")]
    ServiceRegistrationFailed(String),

    #[error("Failed to start enforcement loop: {0}")]
    EnforcementLoopFailed(String),

    #[error("Failed to terminate process {pid}: {reason}")]
    ProcessTerminationFailed { pid: u32, reason: String },

    #[error("Failed to query running processes: {0}")]
    ProcessQueryFailed(String),

    #[error("IPC channel error: {0}")]
    IpcError(String),

    #[error("Windows API error: {0}")]
    WindowsApiError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Shutdown signal received")]
    ShutdownSignal,

    #[error("Core error: {0}")]
    CoreError(#[from] lockin_core::LockError),
}

impl ServiceError {
    /// Convert to exit code for service status.
    pub fn exit_code(&self) -> u32 {
        match self {
            ServiceError::ShutdownSignal => 0, // Clean exit
            _ => 1,                             // Error exit
        }
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;
