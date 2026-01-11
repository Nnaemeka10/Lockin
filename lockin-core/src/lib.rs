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
pub mod error;

// Public API: domain types
pub use domain::{LockDuration, LockRule, LockState};
pub use error::LockError;

// Re-export chrono types for convenience (time domain is public API)
pub use chrono::{DateTime, Duration, Utc};
