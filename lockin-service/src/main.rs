//! Lockin Service: Windows Service for process monitoring and enforcement.
//!
//! This service:
//! - Runs with admin privileges
//! - Monitors process creation
//! - Enforces lock rules via lockin-core
//! - Communicates with UI via IPC
//!
//! Entry point only. Actual logic in submodules.

use std::io;

fn main() -> io::Result<()> {
    // TODO: Phase 6 - Windows Service initialization
    // TODO: Phase 7 - IPC setup
    // TODO: Phase 5 - Process monitoring loop
    
    println!("Lockin Service v0.1.0");
    println!("(Phase 6+ implementation pending)");
    
    Ok(())
}
