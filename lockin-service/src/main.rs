//! Lockin Service: Windows Service for process monitoring and enforcement.
//!
//! This service:
//! - Runs with admin privileges
//! - Monitors process creation
//! - Enforces lock rules via lockin-core
//! - Communicates with UI via IPC
//!
//! Phase 6 entry point for service initialization and enforcement loop.

use lockin_service::service::ServiceManager;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("install") => {
            println!("Installing service...");
            let manager = ServiceManager::new()?;
            manager.register()?;
            println!("Service installed successfully. Use 'net start LockinService' to start.");
            Ok(())
        }

        Some("uninstall") => {
            println!("Uninstalling service...");
            let manager = ServiceManager::new()?;
            manager.unregister()?;
            println!("Service uninstalled successfully.");
            Ok(())
        }

        Some("run") | None => {
            println!("Starting Lockin Service (enforcement mode)...");

            // Phase 6.1: Will load persisted lock state from secure storage
            // Phase 6.1: Will create EnforcementEngine from persisted state
            // Phase 6.1: Will start EnforcementLoop::run() to monitor and enforce

            // Set up service control handler (to receive stop signal)
            let manager = ServiceManager::new()?;
            manager.setup_control_handler()?;

            println!("(Phase 6.1: Service enforcement loop will be initialized here)");

            Ok(())
        }

        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            eprintln!("Usage: lockin-service [install|uninstall|run]");
            Err("Invalid command".into())
        }
    }
}
