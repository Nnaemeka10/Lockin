//! Service Manager: Windows Service integration
//!
//! Phase 6.3: Windows Service Control Manager scaffolding.
//! Full API integration with windows crate planned for Phase 7.

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
    /// Phase 6.3: Scaffolding for service registration.
    /// Full Windows Service Control Manager API integration planned for Phase 7.
    ///
    /// # Errors
    /// Returns ServiceRegistrationFailed if service registration fails.
    pub fn register(&self) -> ServiceResult<()> {
        info!("Registering Windows service: {}", self.config.service_name);
        // Phase 7: Full Windows API implementation with OpenSCManagerA, CreateServiceA
        Ok(())
    }

    /// Unregister the service from Windows (must be run as admin).
    ///
    /// Phase 6.3: Scaffolding for service unregistration.
    /// Full Windows Service Control Manager API integration planned for Phase 7.
    ///
    /// # Errors
    /// Returns ServiceRegistrationFailed if service unregistration fails.
    pub fn unregister(&self) -> ServiceResult<()> {
        info!("Unregistering Windows service: {}", self.config.service_name);
        // Phase 7: Full Windows API implementation with OpenSCManagerA, OpenServiceA, DeleteService
        Ok(())
    }

    /// Start the service.
    ///
    /// # Errors
    /// Returns ServiceStartFailed if service start fails.
    pub fn start(&self) -> ServiceResult<()> {
        info!("Starting service: {}", self.config.service_name);
        Ok(())
    }

    /// Stop the service.
    ///
    /// # Errors
    /// Returns ServiceStopFailed if service stop fails.
    pub fn stop(&self) -> ServiceResult<()> {
        info!("Stopping service: {}", self.config.service_name);
        Ok(())
    }

    /// Get service status.
    ///
    /// # Errors
    /// Returns ServiceStatusFailed if status query fails.
    pub fn status(&self) -> ServiceResult<String> {
        Ok("stopped".to_string())
    }

    /// Set up service control handler for control events.
    ///
    /// Phase 7: Will integrate with Windows service event loop.
    pub fn setup_control_handler(&self) -> ServiceResult<()> {
        info!("Setting up control handler");
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
