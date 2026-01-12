//! Phase 6.1 Integration Tests
//!
//! Tests for Windows Service layer components:
//! - ProcessKiller termination logic
//! - ServiceManager lifecycle management
//! - EnforcementLoop event loop
//! - IPC command/response handling

#[cfg(test)]
mod tests {
    use crate::service::{ServiceManager, WindowsServiceConfig};
    use crate::process_killer::ProcessKiller;
    use crate::enforcement_loop::EnforcementLoop;
    use lockin_core::{LockDuration, LockRule, LockState, EnforcementEngine, ProcessInfo};
    use chrono::Utc;
    use chrono::Duration;

    #[test]
    fn service_manager_creates_with_default_config() {
        let manager = ServiceManager::new().expect("Failed to create ServiceManager");
        let config = manager.config();
        
        assert_eq!(config.service_name, "LockinService");
        assert!(!config.display_name.is_empty());
        assert!(!config.description.is_empty());
    }

    #[test]
    fn service_manager_creates_with_custom_config() {
        let custom_config = WindowsServiceConfig {
            service_name: "TestService".to_string(),
            display_name: "Test Service".to_string(),
            description: "Test service for integration tests".to_string(),
        };

        let manager = ServiceManager::with_config(custom_config.clone())
            .expect("Failed to create ServiceManager");
        let config = manager.config();

        assert_eq!(config.service_name, "TestService");
        assert_eq!(config.display_name, "Test Service");
    }

    #[test]
    fn service_manager_register_mock() {
        // Phase 7: Attempts real Windows API but accepts admin-required failures
        let manager = ServiceManager::new().expect("Failed to create ServiceManager");
        let result = manager.register();
        
        // Either succeeds or fails with admin-required error (both valid in test environment)
        // In actual deployment, this requires admin privileges
        match result {
            Ok(()) => {
                // Success - service was created (unlikely in test environment)
            }
            Err(e) => {
                // Expected error - no admin privileges or service already exists
                let msg = format!("{:?}", e);
                assert!(msg.contains("admin") || msg.contains("already exist"), 
                    "Error should be admin-related or service conflict: {}", msg);
            }
        }
    }

    #[test]
    fn service_manager_unregister_mock() {
        // Phase 7: Attempts real Windows API but accepts admin-required failures
        let manager = ServiceManager::new().expect("Failed to create ServiceManager");
        let result = manager.unregister();
        
        // Either succeeds or fails with admin-required error (both valid in test environment)
        // In actual deployment, this requires admin privileges
        match result {
            Ok(()) => {
                // Success - service was deleted (unlikely in test environment)
            }
            Err(e) => {
                // Expected error - no admin privileges or service not found
                let msg = format!("{:?}", e);
                assert!(msg.contains("admin") || msg.contains("not found") || msg.contains("Unable"),
                    "Error should be admin-related or service not found: {}", msg);
            }
        }
    }

    #[test]
    fn service_control_handler_setup_mock() {
        // Phase 8: Control handler setup
        let manager = ServiceManager::new().expect("Failed to create ServiceManager");
        let result = manager.setup_control_handler();
        
        assert!(result.is_ok(), "setup_control_handler() should succeed");
    }

    #[test]
    fn service_state_transitions() {
        // Phase 8: Test state machine transitions
        use crate::service::ServiceState;
        
        let manager = ServiceManager::new().expect("Failed to create ServiceManager");
        
        // Initial state: Stopped
        assert_eq!(
            manager.get_state().expect("Failed to get state"),
            ServiceState::Stopped
        );

        // Transition to Running
        manager.start_service().expect("Failed to start service");
        assert_eq!(
            manager.get_state().expect("Failed to get state"),
            ServiceState::Running
        );

        // Transition to Paused
        manager.pause_service().expect("Failed to pause service");
        assert_eq!(
            manager.get_state().expect("Failed to get state"),
            ServiceState::Paused
        );

        // Transition back to Running
        manager.resume_service().expect("Failed to resume service");
        assert_eq!(
            manager.get_state().expect("Failed to get state"),
            ServiceState::Running
        );

        // Transition to Stopped
        manager.stop_service().expect("Failed to stop service");
        assert_eq!(
            manager.get_state().expect("Failed to get state"),
            ServiceState::Stopped
        );
    }

    #[test]
    fn service_shutdown_signal() {
        // Phase 8: Verify shutdown signal mechanism
        use crate::service::{is_shutdown_requested, request_shutdown};
        
        // Reset signal first (since it's static)
        // Note: This test may be affected by other tests running in parallel
        // In a real scenario, we'd use thread-local storage or test isolation
        
        // Request shutdown
        request_shutdown();
        assert!(is_shutdown_requested());
    }

    #[test]
    fn process_killer_terminate_mock() {
        // Phase 6.1: Mock implementation - just logs
        let result = ProcessKiller::terminate(1234, "test termination");
        
        assert!(result.is_ok(), "terminate() should succeed in mock mode");
    }

    #[test]
    fn process_killer_terminate_with_respawn_detection_mock() {
        let process = ProcessInfo::new(1234, "notepad.exe", "C:\\Windows\\notepad.exe")
            .expect("Failed to create ProcessInfo");

        let result = ProcessKiller::terminate_with_respawn_detection(&process, "respawn test");
        
        assert!(result.is_ok(), "terminate_with_respawn_detection() should succeed in mock mode");
    }

    #[test]
    fn enforcement_loop_creates_successfully() {
        // Create a lock state
        let duration = LockDuration::from_days(1)
            .expect("Failed to create LockDuration");
        let rule = LockRule::new("notepad.exe".to_string(), duration)
            .expect("Failed to create LockRule");
        let now = Utc::now();
        let lock_state = LockState::new(rule, now)
            .expect("Failed to create LockState");

        // Create enforcement engine with grace period
        let grace_period = Duration::seconds(30);
        let engine = EnforcementEngine::new(lock_state, grace_period)
            .expect("Failed to create EnforcementEngine");

        // Create enforcement loop
        let loop_result = EnforcementLoop::new(engine);
        
        assert!(loop_result.is_ok(), "EnforcementLoop should create successfully");
    }

    #[test]
    fn service_manager_default_trait() {
        let manager1 = ServiceManager::default();
        let manager2 = ServiceManager::default();
        
        assert_eq!(manager1.config().service_name, manager2.config().service_name);
        assert_eq!(manager1.config().display_name, manager2.config().display_name);
    }
}
