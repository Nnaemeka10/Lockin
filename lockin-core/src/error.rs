//! LockError: Comprehensive error types for lock domain operations.
//!
//! Every error is explicit and actionable. No generic failures.

use std::fmt;

/// All failure modes in the lock domain.
///
/// Each variant represents a distinct, recoverable failure state.
/// Errors are never hidden — they propagate to the caller for handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Duration is out of valid range (must be 1 day to 10 years).
    DurationOutOfRange {
        days: i64,
        reason: String,
    },

    /// Duration is negative or zero.
    InvalidDuration {
        duration_days: i64,
    },

    /// Lock start time is in the future (cannot lock retroactively).
    StartTimeInFuture {
        start: String,
        now: String,
    },

    /// Lock end time is in the past (lock is already expired).
    EndTimeInPast {
        end: String,
        now: String,
    },

    /// Attempted to create a lock with an invalid app name.
    InvalidAppName {
        app_name: String,
        reason: String,
    },

    /// Attempted to shorten an existing lock.
    CannotShortenLock {
        current_end: String,
        attempted_new_end: String,
    },

    /// Attempted to move lock end time backward.
    CannotMoveLockBackward {
        current_end: String,
        attempted_end: String,
    },

    /// Lock state is corrupted or inconsistent.
    LockStateCorrupted {
        detail: String,
    },

    /// Generic validation failure (should be rare).
    ValidationFailed {
        message: String,
    },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::DurationOutOfRange { days, reason } => {
                write!(f, "Duration {} days out of range: {}", days, reason)
            }
            LockError::InvalidDuration { duration_days } => {
                write!(
                    f,
                    "Duration must be positive (got {} days)",
                    duration_days
                )
            }
            LockError::StartTimeInFuture { start, now } => {
                write!(
                    f,
                    "Lock start time {} is in the future (now: {})",
                    start, now
                )
            }
            LockError::EndTimeInPast { end, now } => {
                write!(f, "Lock end time {} is in the past (now: {})", end, now)
            }
            LockError::InvalidAppName { app_name, reason } => {
                write!(f, "Invalid app name '{}': {}", app_name, reason)
            }
            LockError::CannotShortenLock {
                current_end,
                attempted_new_end,
            } => {
                write!(
                    f,
                    "Cannot shorten lock: current end {} > attempted end {}",
                    current_end, attempted_new_end
                )
            }
            LockError::CannotMoveLockBackward {
                current_end,
                attempted_end,
            } => {
                write!(
                    f,
                    "Cannot move lock backward: current end {} > attempted end {}",
                    current_end, attempted_end
                )
            }
            LockError::LockStateCorrupted { detail } => {
                write!(f, "Lock state corrupted: {}", detail)
            }
            LockError::ValidationFailed { message } => {
                write!(f, "Validation failed: {}", message)
            }
        }
    }
}

impl std::error::Error for LockError {}
