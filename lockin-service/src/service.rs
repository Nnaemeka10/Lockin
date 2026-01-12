//! Service Manager: Windows Service integration
//!
//! Phase 6.2: Windows Service Control Manager scaffolding.
//! Full API integration deferred to Phase 6.3 when windows crate stabilizes.

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
    /// Phase 6.2: Scaffolding with error handling structure.
    /// Phase 6.3: Will integrate full Windows Service Control Manager API.
    ///
    /// Requirements for Phase 6.3:
    /// - OpenSCManagerA to connect to SCM
    /// - CreateServiceA to register service executable
    /// - Proper SC_HANDLE management
    /// - Error handling for access denied (not admin)
    pub fn register(&self) -> ServiceResult<()> {
        info!("Service registration requested: {}", self.config.service_name);
        info!("Display name: {}", self.config.display_name);
        
        // Phase 6.3: Will implement Windows SCM API calls here
        // For now, indicate what would happen
        info!("Phase 6.3: Will call OpenSCManagerA + CreateServiceA");
        
        Ok(())
    }

    /// Unregister the service (must be run as admin).
    ///
    /// Phase 6.2: Scaffolding with error handling structure.
    /// Phase 6.3: Will integrate full Windows Service Control Manager API.
    ///
    /// Requirements for Phase 6.3:
    /// - OpenSCManagerA to connect to SCM
    /// - OpenServiceA to open the service
    /// - DeleteService to remove it
    /// - Proper handle management
    pub fn unregister(&self) -> ServiceResult<()> {
        info!("Service unregistration requested: {}", self.config.service_name);
        
        // Phase 6.3: Will implement Windows SCM API calls here
        // For now, indicate what would happen
        info!("Phase 6.3: Will call OpenSCManagerA + OpenServiceA + DeleteService");
        
        Ok(())
    }

    /// Set up service control handler (to receive stop signals).
    ///
    /// Phase 6.2: Skeleton for Windows Service Status management.
    /// Full RegisterServiceCtrlHandlerA integration deferred to Phase 6.3.
    ///
    /// Future implementation will:
    /// - Register control handler callback with SCM
    /// - Handle SERVICE_CONTROL_STOP signal
    /// - Handle SERVICE_CONTROL_PAUSE and SERVICE_CONTROL_CONTINUE
    /// - Update service status via SetServiceStatus
    pub fn setup_control_handler() -> ServiceResult<()> {
        info!("Service control handler setup (Phase 6.2 - structure ready for Phase 6.3 callbacks)");
        
        // Phase 6.3: Will integrate RegisterServiceCtrlHandlerA and SetServiceStatus
        // This requires careful callback management and Windows API complexity
        // that is better deferred for cleaner integration
        
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
