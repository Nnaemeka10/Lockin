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

    /// Wall-clock time has moved backward (rollback detected).
    TimeRollbackDetected {
        previous_time: String,
        current_time: String,
        rollback_amount_ms: i64,
    },

    /// Monotonic time is inconsistent (should never happen on same device).
    MonotonicTimeInconsistent {
        expected_at_least_ms: u128,
        observed_ms: u128,
    },

    /// Time anchor is invalid or corrupted.
    InvalidTimeAnchor {
        reason: String,
    },

    /// Attempt to validate time without any anchors (no reference point).
    NoTimeAnchor {
        reason: String,
    },

    /// Persistence layer: encryption key is invalid or too short.
    InvalidEncryptionKey {
        reason: String,
    },

    /// Persistence layer: failed to encrypt lock state.
    EncryptionFailed {
        reason: String,
    },

    /// Persistence layer: failed to decrypt lock state.
    DecryptionFailed {
        reason: String,
    },

    /// Persistence layer: integrity check failed (file was tampered with).
    IntegrityCheckFailed {
        expected_hmac: String,
        computed_hmac: String,
    },

    /// Persistence layer: serialization failed.
    SerializationFailed {
        reason: String,
    },

    /// Persistence layer: deserialization failed.
    DeserializationFailed {
        reason: String,
    },

    /// Persistence layer: loaded state is inconsistent or corrupted.
    LoadedStateInvalid {
        reason: String,
    },

    /// Persistence layer: file I/O error.
    FileIoError {
        reason: String,
    },

    /// Process detection: failed to enumerate running processes.
    ProcessEnumerationFailed {
        reason: String,
    },

    /// Process detection: could not read process information.
    ProcessQueryFailed {
        pid: u32,
        reason: String,
    },

    /// Process detection: path normalization failed.
    PathNormalizationFailed {
        path: String,
        reason: String,
    },

    /// Process detection: could not get executable path for process.
    ExecutablePathNotFound {
        pid: u32,
        reason: String,
    },

    /// Process detection: no matching processes found for app.
    NoMatchingProcesses {
        app_name: String,
        searched_count: usize,
    },

    /// Enforcement: grace period configuration is invalid.
    InvalidGracePeriod {
        reason: String,
    },

    /// Enforcement: attempted to terminate process that is not currently tracked.
    ProcessNotTracked {
        pid: u32,
    },

    /// Enforcement: respawn detection logic failed.
    RespawnDetectionFailed {
        reason: String,
    },

    /// Enforcement: cannot apply enforcement (lock not active, etc).
    EnforcementNotApplicable {
        reason: String,
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
            LockError::TimeRollbackDetected {
                previous_time,
                current_time,
                rollback_amount_ms,
            } => {
                write!(
                    f,
                    "Time rollback detected: was {} now {}, rollback {} ms",
                    previous_time, current_time, rollback_amount_ms
                )
            }
            LockError::MonotonicTimeInconsistent {
                expected_at_least_ms,
                observed_ms,
            } => {
                write!(
                    f,
                    "Monotonic time inconsistent: expected at least {}ms, observed {}ms",
                    expected_at_least_ms, observed_ms
                )
            }
            LockError::InvalidTimeAnchor { reason } => {
                write!(f, "Invalid time anchor: {}", reason)
            }
            LockError::NoTimeAnchor { reason } => {
                write!(f, "No time anchor: {}", reason)
            }
            LockError::InvalidEncryptionKey { reason } => {
                write!(f, "Invalid encryption key: {}", reason)
            }
            LockError::EncryptionFailed { reason } => {
                write!(f, "Encryption failed: {}", reason)
            }
            LockError::DecryptionFailed { reason } => {
                write!(f, "Decryption failed: {}", reason)
            }
            LockError::IntegrityCheckFailed {
                expected_hmac,
                computed_hmac,
            } => {
                write!(
                    f,
                    "Integrity check failed: expected {} but computed {}",
                    expected_hmac, computed_hmac
                )
            }
            LockError::SerializationFailed { reason } => {
                write!(f, "Serialization failed: {}", reason)
            }
            LockError::DeserializationFailed { reason } => {
                write!(f, "Deserialization failed: {}", reason)
            }
            LockError::LoadedStateInvalid { reason } => {
                write!(f, "Loaded state invalid: {}", reason)
            }
            LockError::FileIoError { reason } => {
                write!(f, "File I/O error: {}", reason)
            }
            LockError::ProcessEnumerationFailed { reason } => {
                write!(f, "Process enumeration failed: {}", reason)
            }
            LockError::ProcessQueryFailed { pid, reason } => {
                write!(f, "Failed to query process {}: {}", pid, reason)
            }
            LockError::PathNormalizationFailed { path, reason } => {
                write!(f, "Failed to normalize path '{}': {}", path, reason)
            }
            LockError::ExecutablePathNotFound { pid, reason } => {
                write!(f, "Could not get executable path for process {}: {}", pid, reason)
            }
            LockError::NoMatchingProcesses {
                app_name,
                searched_count,
            } => {
                write!(
                    f,
                    "No processes matching '{}' found (searched {} processes)",
                    app_name, searched_count
                )
            }
            LockError::InvalidGracePeriod { reason } => {
                write!(f, "Invalid grace period: {}", reason)
            }
            LockError::ProcessNotTracked { pid } => {
                write!(f, "Process {} is not currently tracked", pid)
            }
            LockError::RespawnDetectionFailed { reason } => {
                write!(f, "Respawn detection failed: {}", reason)
            }
            LockError::EnforcementNotApplicable { reason } => {
                write!(f, "Enforcement not applicable: {}", reason)
            }
        }
    }
}

impl std::error::Error for LockError {}
