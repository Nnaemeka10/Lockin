//! Service Manager: Windows Service integration
//!
//! Phase 6: Skeleton (service control handler setup).
//! Phase 6.1: Integrate Windows Service Control Manager API.

use crate::error::ServiceResult;
use tracing::info;

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

/// Manages Windows service lifecycle.
pub struct ServiceManager {
    config: WindowsServiceConfig,
}

impl ServiceManager {
    /// Create a new service manager with default config.
    pub fn new() -> ServiceResult<Self> {
        Ok(ServiceManager {
            config: WindowsServiceConfig::default(),
        })
    }

    /// Create with custom config.
    pub fn with_config(config: WindowsServiceConfig) -> ServiceResult<Self> {
        Ok(ServiceManager { config })
    }

    /// Register the service in Windows (must be run as admin).
    ///
    /// Phase 6.1: Will use CreateServiceA API.
    pub fn register(&self) -> ServiceResult<()> {
        info!("Service registration (mock): {}", self.config.service_name);

        // Phase 6.1: Will implement with Windows Service API:
        // OpenSCManagerA(null, null, SC_MANAGER_ALL_ACCESS)
        // CreateServiceA(scm, name, display_name, ...)
        // CloseServiceHandle(scm)

        Ok(())
    }

    /// Unregister the service (must be run as admin).
    pub fn unregister(&self) -> ServiceResult<()> {
        info!(
            "Service unregistration (mock): {}",
            self.config.service_name
        );

        // Phase 6.1: Will implement with Windows Service API:
        // OpenSCManagerA(null, null, SC_MANAGER_ALL_ACCESS)
        // OpenServiceA(scm, name, DELETE)
        // DeleteService(service)
        // CloseServiceHandle(...)

        Ok(())
    }

    /// Set up service control handler (to receive stop signals).
    ///
    /// Phase 6.1: Will use SetServiceStatus API.
    pub fn setup_control_handler() -> ServiceResult<()> {
        info!("Service control handler setup (mock)");

        // Phase 6.1: Will implement with Windows Service API:
        // RegisterServiceCtrlHandlerA(name, handler_fn)
        // handler_fn receives: SERVICE_CONTROL_STOP, etc.

        Ok(())
    }

    /// Get service config.
    pub fn config(&self) -> &WindowsServiceConfig {
        &self.config
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        ServiceManager::new().expect("Failed to create default ServiceManager")
    }
}
