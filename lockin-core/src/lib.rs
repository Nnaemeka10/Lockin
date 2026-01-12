//! Lockin Core: Immutable lock domain model and anti-rollback logic.
//!
//! This crate contains:
//! - Lock state and rules (immutable, invariant-enforced)
//! - Time enforcement logic (wall-clock vs monotonic)
//! - Secure persistence (encrypted, integrity-checked)
//! - Process identity (safe, normalized)
//!
//! No Windows APIs. Platform-agnostic. Source of truth for all lock logic.

pub mod domain;
pub mod time;
pub mod persistence;
pub mod process;
pub mod enforcement;
pub mod error;

// Public API: domain types
pub use domain::{LockDuration, LockRule, LockState};
pub use error::LockError;

// Public API: time types
pub use time::{TimeAnchor, TimeValidator};

// Public API: persistence types
pub use persistence::{EncryptedLockStore, EncryptedSnapshot, LockStateSnapshot};

// Public API: process types
pub use process::{ProcessInfo, ProcessMatcher, ProcessQuery};

// Public API: enforcement types
pub use enforcement::{EnforcementAction, EnforcementEngine, GracePeriod, ProcessTerminationLog, RespawnDetector};

// Re-export chrono types for convenience (time domain is public API)
pub use chrono::{DateTime, Duration, Utc};
