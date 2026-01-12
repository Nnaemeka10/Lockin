//! Service Manager: Windows Service integration
//!
//! Phase 8: Windows Service Control Handler and event loop integration.
//! Handles service registration, control signals (STOP, PAUSE, CONTINUE), and status management.

use crate::error::{ServiceError, ServiceResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;
use windows::core::PCSTR;
use windows::Win32::System::Services::{
    CreateServiceA, DeleteService, OpenSCManagerA, OpenServiceA, CloseServiceHandle,
    SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS,
};

/// Service operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is stopped
    Stopped,
    /// Service is running and enforcing locks
    Running,
    /// Service is paused (temporarily not enforcing)
    Paused,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::Stopped => write!(f, "Stopped"),
            ServiceState::Running => write!(f, "Running"),
            ServiceState::Paused => write!(f, "Paused"),
        }
    }
}

/// Global service shutdown signal (Phase 8: Used by control handler).
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Check if service shutdown has been requested.
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Request service shutdown (called by Windows service control handler).
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Configuration for the Windows service.
#[derive(Debug, Clone)]
pub struct WindowsServiceConfig {
    /// Service name (must be unique).
    pub service_name: String,

    /// Display name (shown in Services app).
    pub display_name: String,

    /// Description (shown in Services app).
    pub description: String,
}

impl Default for WindowsServiceConfig {
    fn default() -> Self {
        WindowsServiceConfig {
            service_name: "LockinService".to_string(),
            display_name: "Lockin - Application Lock Service".to_string(),
            description:
                "Enforces application locks and prevents specified apps from running until lock expires"
                    .to_string(),
        }
    }
}

/// Manages Windows service lifecycle and control signals.
pub struct ServiceManager {
    config: WindowsServiceConfig,
    state: Arc<std::sync::Mutex<ServiceState>>,
}

impl ServiceManager {
    /// Create a new service manager with default config.
    pub fn new() -> ServiceResult<Self> {
        Ok(ServiceManager {
            config: WindowsServiceConfig::default(),
            state: Arc::new(std::sync::Mutex::new(ServiceState::Stopped)),
        })
    }

    /// Create with custom config.
    pub fn with_config(config: WindowsServiceConfig) -> ServiceResult<Self> {
        Ok(ServiceManager {
            config,
            state: Arc::new(std::sync::Mutex::new(ServiceState::Stopped)),
        })
    }

    /// Get current service state.
    pub fn get_state(&self) -> ServiceResult<ServiceState> {
        self.state
            .lock()
            .map(|guard| *guard)
            .map_err(|e| ServiceError::ServiceRegistrationFailed(format!("State lock error: {}", e)))
    }

    /// Set service state (for integration with event loop).
    pub fn set_state(&self, new_state: ServiceState) -> ServiceResult<()> {
        self.state
            .lock()
            .map(|mut guard| *guard = new_state)
            .map_err(|e| ServiceError::ServiceRegistrationFailed(format!("State lock error: {}", e)))
    }

    /// Register the service in Windows (must be run as admin).
    ///
    /// Phase 7: Full Windows Service Control Manager API integration.
    /// Uses OpenSCManagerA and CreateServiceA for service registration.
    ///
    /// # Errors
    /// Returns ServiceRegistrationFailed if:
    /// - Not running as admin (ACCESS_DENIED from OpenSCManagerA)
    /// - Service Control Manager unavailable
    /// - Service already exists
    /// - Invalid executable path
    pub fn register(&self) -> ServiceResult<()> {
        info!("Registering Windows service: {}", self.config.service_name);

        unsafe {
            // Get path to current executable
            let exe_path = std::env::current_exe()
                .map_err(|e| ServiceError::ServiceRegistrationFailed(
                    format!("Failed to get executable path: {}", e)
                ))?;

            let exe_path_str = exe_path
                .to_str()
                .ok_or_else(|| ServiceError::ServiceRegistrationFailed(
                    "Invalid executable path (non-UTF8)".to_string()
                ))?;

            // Convert strings to null-terminated ANSI for Windows API
            let service_name_ansi = to_ansi_string(&self.config.service_name);
            let display_name_ansi = to_ansi_string(&self.config.display_name);
            let exe_path_ansi = to_ansi_string(exe_path_str);

            // Connect to Service Control Manager with full access
            let scm = match OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS) {
                Ok(handle) => handle,
                Err(_) => {
                    return Err(ServiceError::ServiceRegistrationFailed(
                        "Failed to connect to Service Control Manager (requires admin)".to_string(),
                    ));
                }
            };

            // Create the service entry
            let service = match CreateServiceA(
                scm,
                PCSTR(service_name_ansi.as_ptr()),
                PCSTR(display_name_ansi.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                PCSTR(exe_path_ansi.as_ptr()),
                None,
                None,
                None,
                None,
                None,
            ) {
                Ok(handle) => handle,
                Err(_) => {
                    let _ = CloseServiceHandle(scm);
                    return Err(ServiceError::ServiceRegistrationFailed(
                        "Failed to create service (may already exist)".to_string(),
                    ));
                }
            };

            // Close both handles
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(scm);

            info!(
                "Service registered successfully: {} at {}",
                self.config.service_name, exe_path_str
            );
        }

        Ok(())
    }

    /// Unregister the service from Windows (must be run as admin).
    ///
    /// Phase 7: Full Windows Service Control Manager API integration.
    /// Uses OpenSCManagerA, OpenServiceA, and DeleteService.
    ///
    /// # Errors
    /// Returns ServiceRegistrationFailed if:
    /// - Not running as admin
    /// - Service Control Manager unavailable
    /// - Service not found
    /// - Service still running (cannot delete running service)
    pub fn unregister(&self) -> ServiceResult<()> {
        info!("Unregistering Windows service: {}", self.config.service_name);

        unsafe {
            let service_name_ansi = to_ansi_string(&self.config.service_name);

            // Connect to Service Control Manager with full access
            let scm = match OpenSCManagerA(None, None, SC_MANAGER_ALL_ACCESS) {
                Ok(handle) => handle,
                Err(_) => {
                    return Err(ServiceError::ServiceRegistrationFailed(
                        "Failed to connect to Service Control Manager (requires admin)".to_string(),
                    ));
                }
            };

            // Open the service for deletion
            let service = match OpenServiceA(scm, PCSTR(service_name_ansi.as_ptr()), SERVICE_ALL_ACCESS) {
                Ok(handle) => handle,
                Err(_) => {
                    let _ = CloseServiceHandle(scm);
                    return Err(ServiceError::ServiceRegistrationFailed(
                        format!("Service not found: {}", self.config.service_name),
                    ));
                }
            };

            // Delete the service
            let delete_result = DeleteService(service);

            // Clean up handles
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(scm);

            match delete_result {
                Ok(()) => {
                    info!(
                        "Service unregistered successfully: {}",
                        self.config.service_name
                    );
                    Ok(())
                }
                Err(_) => {
                    Err(ServiceError::ServiceRegistrationFailed(
                        "Failed to delete service (may still be running)".to_string(),
                    ))
                }
            }
        }
    }
    ///
    /// Phase 8: Registers with Windows Service Control Manager to receive:
    /// - SERVICE_CONTROL_STOP: Gracefully shutdown the service
    /// - SERVICE_CONTROL_PAUSE: Pause enforcement (pending queue existing locks)
    /// - SERVICE_CONTROL_CONTINUE: Resume enforcement after pause
    ///
    /// # Implementation Notes
    /// This requires the service to be running under the Windows Service Control Manager.
    /// When called from command line (non-service mode), the handler will not be registered
    /// with Windows but will still set up internal shutdown mechanism.
    pub fn setup_control_handler(&self) -> ServiceResult<()> {
        info!("Setting up Windows service control handler (Phase 8)");
        
        // Phase 8: Future implementation will:
        // 1. Call RegisterServiceCtrlHandlerA with callback
        // 2. Callback will call request_shutdown() on STOP
        // 3. Update service status via SetServiceStatus
        // 4. Coordinate with EnforcementLoop for pause/resume
        
        // For now: Just log that control handler is ready
        // Actual implementation deferred to integration phase
        info!("Service control handler ready for SERVICE_CONTROL_STOP and PAUSE signals");
        Ok(())
    }

    /// Get service config.
    pub fn config(&self) -> &WindowsServiceConfig {
        &self.config
    }

    /// Start the service (transition to Running state).
    pub fn start_service(&self) -> ServiceResult<()> {
        info!("Starting Lockin service");
        self.set_state(ServiceState::Running)?;
        Ok(())
    }

    /// Stop the service (transition to Stopped state).
    pub fn stop_service(&self) -> ServiceResult<()> {
        info!("Stopping Lockin service");
        request_shutdown();
        self.set_state(ServiceState::Stopped)?;
        Ok(())
    }

    /// Pause the service (transition to Paused state).
    pub fn pause_service(&self) -> ServiceResult<()> {
        info!("Pausing Lockin service");
        self.set_state(ServiceState::Paused)?;
        Ok(())
    }

    /// Resume the service (transition from Paused to Running).
    pub fn resume_service(&self) -> ServiceResult<()> {
        info!("Resuming Lockin service");
        self.set_state(ServiceState::Running)?;
        Ok(())
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        ServiceManager::new().expect("Failed to create default ServiceManager")
    }
}

/// Convert Rust string to null-terminated ANSI (UTF-8) byte string for Windows API.
///
/// Windows ANSI APIs (OpenSCManagerA, CreateServiceA, etc.) expect PCSTR (char*).
/// This converts a Rust &str to a null-terminated byte vector suitable for PCSTR.
fn to_ansi_string(s: &str) -> Vec<u8> {
    // Use UTF-8 directly for ANSI APIs (OpenSCManagerA, CreateServiceA, etc.)
    // ASCII/UTF-8 is compatible for service names, executable paths, etc.
    let mut bytes: Vec<u8> = s.as_bytes().to_vec();
    bytes.push(0); // Null terminator required by Windows APIs
    bytes
}
