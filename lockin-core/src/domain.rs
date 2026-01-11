//! Domain: Immutable lock types with invariant enforcement.
//!
//! This module encodes lock semantics in the type system:
//! - Lock duration is immutable (newtype wrapper)
//! - Lock rules are immutable (no modification after creation)
//! - Lock state cannot be manually shortened (computed from start + duration)
//! - End times cannot move backward
//!
//! All invariants are enforced at construction time via `Result<T, LockError>`.

use crate::error::LockError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

// ============================================================================
// LockDuration: Immutable, validated duration
// ============================================================================

/// A validated lock duration.
///
/// Invariants:
/// - Minimum: 1 day
/// - Maximum: 10 years
/// - No negative values
/// - Immutable after construction
///
/// Uses `newtype` pattern to prevent accidental misuse as plain `Duration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockDuration(Duration);

impl LockDuration {
    /// Minimum allowed duration: 1 day.
    const MIN_DAYS: i64 = 1;

    /// Maximum allowed duration: 10 years (approximation: 3650 days).
    const MAX_DAYS: i64 = 3650;

    /// Create a lock duration from days.
    ///
    /// Returns error if:
    /// - `days < 1` (too short)
    /// - `days > 3650` (too long, ~10 years)
    ///
    /// # Example
    /// ```ignore
    /// let duration = LockDuration::from_days(7)?;
    /// ```
    pub fn from_days(days: i64) -> Result<Self, LockError> {
        if days < Self::MIN_DAYS {
            return Err(LockError::InvalidDuration {
                duration_days: days,
            });
        }

        if days > Self::MAX_DAYS {
            return Err(LockError::DurationOutOfRange {
                days,
                reason: format!(
                    "Exceeds maximum of {} days (~10 years)",
                    Self::MAX_DAYS
                ),
            });
        }

        Ok(LockDuration(Duration::days(days)))
    }

    /// Get the underlying `chrono::Duration`.
    pub fn as_duration(&self) -> Duration {
        self.0
    }

    /// Get the duration in days (truncated).
    pub fn days(&self) -> i64 {
        self.0.num_days()
    }
}

// ============================================================================
// LockRule: Immutable specification of a lock
// ============================================================================

/// A specification for locking a single application.
///
/// Invariants:
/// - App name is non-empty, valid executable
/// - Duration is valid (see `LockDuration`)
/// - Immutable after construction
/// - Does not contain execution state (start time, etc.)
///
/// `LockRule` represents the **intent** to lock an app.
/// `LockState` represents the **execution** of that intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRule {
    /// Target application (e.g., "Firefox.exe", "Discord.exe").
    /// Normalized to lowercase for case-insensitive comparison.
    app_name: String,

    /// How long to lock the app for.
    duration: LockDuration,
}

impl LockRule {
    /// Create a lock rule.
    ///
    /// Returns error if:
    /// - `app_name` is empty or contains invalid characters
    /// - `duration` is invalid
    pub fn new(app_name: impl Into<String>, duration: LockDuration) -> Result<Self, LockError> {
        let app_name = app_name.into();

        // Validation: non-empty, contains only valid filename characters
        if app_name.trim().is_empty() {
            return Err(LockError::InvalidAppName {
                app_name: app_name.clone(),
                reason: "App name cannot be empty".to_string(),
            });
        }

        // Normalize to lowercase for case-insensitive matching
        let normalized = app_name.to_lowercase();

        // Basic validation: no path separators, no absolute paths
        if normalized.contains('\\') || normalized.contains('/') {
            return Err(LockError::InvalidAppName {
                app_name: app_name.clone(),
                reason: "App name must be a filename, not a path".to_string(),
            });
        }

        // Must end with common executable extension
        if !normalized.ends_with(".exe")
            && !normalized.ends_with(".com")
            && !normalized.ends_with(".bat")
        {
            return Err(LockError::InvalidAppName {
                app_name: app_name.clone(),
                reason: "App name must end with .exe, .com, or .bat".to_string(),
            });
        }

        Ok(LockRule {
            app_name: normalized,
            duration,
        })
    }

    /// Get the app name (normalized to lowercase).
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Get the lock duration.
    pub fn duration(&self) -> LockDuration {
        self.duration
    }
}

// ============================================================================
// LockState: Immutable lock execution state
// ============================================================================

/// The active state of a lock.
///
/// Invariants:
/// - `start_time` is never in the future
/// - `end_time` is computed from `start_time + duration` (never modified directly)
/// - `end_time` can never move backward
/// - `end_time` can never be shortened
/// - Immutable after construction
///
/// Key design: `LockState` has no public constructor that lets you set `end_time`.
/// Instead, `end_time` is always computed from `start_time + duration`.
/// This makes it impossible to create invalid states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockState {
    /// The rule that created this state.
    rule: LockRule,

    /// When the lock was activated (wall-clock time).
    /// Must be now or in the past.
    start_time: DateTime<Utc>,

    /// When the lock expires (computed from start_time + duration).
    /// Derived, immutable, and cannot move backward.
    end_time: DateTime<Utc>,
}

impl LockState {
    /// Create an active lock state.
    ///
    /// The `end_time` is computed as `start_time + rule.duration`.
    ///
    /// Returns error if:
    /// - `start_time` is in the future
    /// - `end_time` would be in the past (start_time is too old)
    ///
    /// # Example
    /// ```ignore
    /// let rule = LockRule::new("Firefox.exe", LockDuration::from_days(7)?)?;
    /// let lock = LockState::new(rule, Utc::now())?;
    /// ```
    pub fn new(rule: LockRule, start_time: DateTime<Utc>) -> Result<Self, LockError> {
        let now = Utc::now();

        // Invariant 1: start_time must not be in the future
        if start_time > now {
            return Err(LockError::StartTimeInFuture {
                start: start_time.to_rfc3339(),
                now: now.to_rfc3339(),
            });
        }

        // Compute end_time from start + duration
        let end_time = start_time + rule.duration.as_duration();

        // Invariant 2: end_time must not be in the past
        // (This catches the case where start_time is too old)
        if end_time < now {
            return Err(LockError::EndTimeInPast {
                end: end_time.to_rfc3339(),
                now: now.to_rfc3339(),
            });
        }

        Ok(LockState {
            rule,
            start_time,
            end_time,
        })
    }

    /// Check if the lock is still active.
    ///
    /// Returns `true` if the current time is before `end_time`.
    pub fn is_active(&self) -> bool {
        Utc::now() < self.end_time
    }

    /// Get the time remaining until the lock expires.
    ///
    /// Returns `None` if the lock has expired.
    pub fn time_remaining(&self) -> Option<Duration> {
        let now = Utc::now();
        if now < self.end_time {
            Some(self.end_time - now)
        } else {
            None
        }
    }

    /// Get the rule that created this lock.
    pub fn rule(&self) -> &LockRule {
        &self.rule
    }

    /// Get the start time (when the lock was activated).
    pub fn start_time(&self) -> DateTime<Utc> {
        self.start_time
    }

    /// Get the end time (when the lock expires).
    pub fn end_time(&self) -> DateTime<Utc> {
        self.end_time
    }

    /// Verify that a potential new end time would not violate invariants.
    ///
    /// This is used by Phase 3 (persistence) to validate deserialized state.
    /// Returns `Err` if:
    /// - `new_end_time` is before `self.end_time` (trying to shorten)
    /// - `new_end_time` violates other constraints
    pub fn validate_end_time_extension(&self, new_end_time: DateTime<Utc>) -> Result<(), LockError> {
        match new_end_time.cmp(&self.end_time) {
            Ordering::Less => {
                Err(LockError::CannotShortenLock {
                    current_end: self.end_time.to_rfc3339(),
                    attempted_new_end: new_end_time.to_rfc3339(),
                })
            }
            Ordering::Equal => Ok(()),
            Ordering::Greater => Ok(()),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_duration_min_boundary() {
        // Minimum valid duration: 1 day
        let duration = LockDuration::from_days(1);
        assert!(duration.is_ok());

        // Zero days: invalid
        let duration = LockDuration::from_days(0);
        assert!(duration.is_err());

        // Negative days: invalid
        let duration = LockDuration::from_days(-1);
        assert!(duration.is_err());
    }

    #[test]
    fn lock_duration_max_boundary() {
        // Maximum valid duration: 3650 days
        let duration = LockDuration::from_days(3650);
        assert!(duration.is_ok());

        // Over maximum: invalid
        let duration = LockDuration::from_days(3651);
        assert!(duration.is_err());
    }

    #[test]
    fn lock_rule_valid_app_name() {
        let duration = LockDuration::from_days(7).unwrap();

        // Valid .exe name
        let rule = LockRule::new("Firefox.exe", duration);
        assert!(rule.is_ok());

        // Normalized to lowercase
        let rule = LockRule::new("FIREFOX.EXE", duration).unwrap();
        assert_eq!(rule.app_name(), "firefox.exe");
    }

    #[test]
    fn lock_rule_invalid_app_name() {
        let duration = LockDuration::from_days(7).unwrap();

        // Empty name
        let rule = LockRule::new("", duration);
        assert!(rule.is_err());

        // No extension
        let rule = LockRule::new("Firefox", duration);
        assert!(rule.is_err());

        // Path separator (not a filename)
        let rule = LockRule::new("C:\\Firefox.exe", duration);
        assert!(rule.is_err());
    }

    #[test]
    fn lock_state_cannot_have_future_start() {
        let duration = LockDuration::from_days(7).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();

        // Start time in the future
        let future = Utc::now() + Duration::hours(1);
        let lock = LockState::new(rule, future);
        assert!(lock.is_err());
    }

    #[test]
    fn lock_state_cannot_have_past_end() {
        let duration = LockDuration::from_days(1).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();

        // Start time too far in the past (end time is now in the past)
        let past = Utc::now() - Duration::days(2);
        let lock = LockState::new(rule, past);
        assert!(lock.is_err());
    }

    #[test]
    fn lock_state_valid_creation() {
        let duration = LockDuration::from_days(7).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();

        // Start time is now (or a few seconds ago)
        let start = Utc::now() - Duration::seconds(1);
        let lock = LockState::new(rule, start);
        assert!(lock.is_ok());
    }

    #[test]
    fn lock_state_is_active() {
        let duration = LockDuration::from_days(7).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();
        let start = Utc::now() - Duration::seconds(1);
        let lock = LockState::new(rule, start).unwrap();

        // Should be active (lock is 7 days long)
        assert!(lock.is_active());
    }

    #[test]
    fn lock_state_time_remaining() {
        let duration = LockDuration::from_days(7).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();
        let start = Utc::now() - Duration::seconds(1);
        let lock = LockState::new(rule, start).unwrap();

        // Should have time remaining
        let remaining = lock.time_remaining();
        assert!(remaining.is_some());
        let remaining = remaining.unwrap();
        // Should be close to 7 days (minus 1 second)
        assert!(remaining.num_days() >= 6 && remaining.num_days() <= 7);
    }

    #[test]
    fn lock_state_cannot_shorten() {
        let duration = LockDuration::from_days(7).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();
        let start = Utc::now() - Duration::seconds(1);
        let lock = LockState::new(rule, start).unwrap();

        // Attempt to shorten the lock
        let shorter_end = lock.end_time() - Duration::days(1);
        let result = lock.validate_end_time_extension(shorter_end);
        assert!(result.is_err());
    }

    #[test]
    fn lock_state_can_extend() {
        let duration = LockDuration::from_days(7).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();
        let start = Utc::now() - Duration::seconds(1);
        let lock = LockState::new(rule, start).unwrap();

        // Attempt to extend the lock
        let longer_end = lock.end_time() + Duration::days(1);
        let result = lock.validate_end_time_extension(longer_end);
        assert!(result.is_ok());
    }
}
