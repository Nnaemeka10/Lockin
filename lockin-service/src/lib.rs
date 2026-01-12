//! Lockin Service - Windows Service integration layer.
//!
//! Provides OS-level process management and enforcement orchestration.
//! Integrates lockin-core domain logic with Windows Service APIs.

pub mod enforcement_loop;
pub mod error;
pub mod ipc;
pub mod process_killer;
pub mod service;

pub use error::{ServiceError, ServiceResult};
pub use service::{ServiceManager, WindowsServiceConfig};
