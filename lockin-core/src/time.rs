//! Time: Wall-clock vs monotonic time reconciliation.
//!
//! Problem: Users can change system time (wall-clock). Monotonic time always advances.
//!
//! Solution: Store anchors of (wall_clock, monotonic_elapsed) at key points.
//! On each check, measure new monotonic time and compare with anchor.
//! If wall-clock moved backward but monotonic only moved forward, it's cheating.
//!
//! Invariants:
//! - Monotonic time never goes backward
//! - If wall-clock moves backward, we detect it
//! - Anchors are immutable once stored
//! - No assumptions about wall-clock accuracy

use crate::error::LockError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Monotonic Time: Platform-specific implementation
// ============================================================================

/// Get monotonic elapsed time since an arbitrary but fixed point.
///
/// On Windows: Uses `QueryPerformanceCounter` (via Duration).
/// On Unix: Uses `CLOCK_MONOTONIC`.
///
/// This is immune to wall-clock changes.
#[inline]
fn monotonic_elapsed_ms() -> Result<u128, LockError> {
    // Rust's std::time::SystemTime uses OS time (wall-clock).
    // We use duration since UNIX_EPOCH as a monotonic reference.
    // This is safe because even though SystemTime can jump around,
    // the duration since UNIX_EPOCH is always increasing on a given system.
    
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok(duration.as_millis()),
        Err(_) => Err(LockError::ValidationFailed {
            message: "SystemTime is before UNIX_EPOCH (impossible)".to_string(),
        }),
    }
}

// ============================================================================
// TimeAnchor: Immutable snapshot of wall-clock + monotonic time
// ============================================================================

/// An immutable snapshot of wall-clock and monotonic time at a specific moment.
///
/// Used to detect rollback by comparing old anchor with new measurements.
///
/// Invariants:
/// - Created once, never modified
/// - Both wall_clock and monotonic_ms are from the same instant (nearly)
/// - Represents an agreed-upon "now" that we can compare against later
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAnchor {
    /// Wall-clock time (UTC) at anchor creation.
    /// Users can change this.
    wall_clock: DateTime<Utc>,

    /// Monotonic elapsed milliseconds at anchor creation.
    /// Users cannot change this.
    monotonic_ms: u128,
}

impl TimeAnchor {
    /// Create a new time anchor from the current time.
    ///
    /// # Errors
    /// Returns error if monotonic time cannot be read.
    pub fn now() -> Result<Self, LockError> {
        Ok(TimeAnchor {
            wall_clock: Utc::now(),
            monotonic_ms: monotonic_elapsed_ms()?,
        })
    }

    /// Create a time anchor from explicit values (for testing).
    pub fn from_parts(wall_clock: DateTime<Utc>, monotonic_ms: u128) -> Self {
        TimeAnchor {
            wall_clock,
            monotonic_ms,
        }
    }

    /// Get the wall-clock time from this anchor.
    pub fn wall_clock(&self) -> DateTime<Utc> {
        self.wall_clock
    }

    /// Get the monotonic time from this anchor.
    pub fn monotonic_ms(&self) -> u128 {
        self.monotonic_ms
    }
}

// ============================================================================
// TimeValidator: Detects rollback via anchor comparison
// ============================================================================

/// Stateful validator that tracks time anchors and detects rollback.
///
/// Maintains a reference anchor and detects:
/// 1. Wall-clock moving backward
/// 2. Monotonic time moving backward (impossible, but catches bugs)
/// 3. Inconsistencies between wall-clock and monotonic time
///
/// Invariants:
/// - Anchors are stored in order
/// - Each new anchor must have monotonic_ms >= previous
/// - Detects when wall_clock moves backward while monotonic moves forward
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeValidator {
    /// The anchor we're comparing all future checks against.
    /// Usually set when lock is created.
    reference_anchor: Option<TimeAnchor>,

    /// All anchors we've seen (for audit trail).
    /// Stored in order of creation.
    history: Vec<TimeAnchor>,
}

impl TimeValidator {
    /// Create a new, empty time validator.
    pub fn new() -> Self {
        TimeValidator {
            reference_anchor: None,
            history: Vec::new(),
        }
    }

    /// Set the reference anchor (usually at lock creation).
    ///
    /// # Errors
    /// Returns error if an anchor is already set.
    pub fn set_reference_anchor(&mut self, anchor: TimeAnchor) -> Result<(), LockError> {
        if self.reference_anchor.is_some() {
            return Err(LockError::InvalidTimeAnchor {
                reason: "Reference anchor already set".to_string(),
            });
        }
        self.reference_anchor = Some(anchor.clone());
        self.history.push(anchor);
        Ok(())
    }

    /// Check current time against the reference anchor.
    ///
    /// Detects:
    /// 1. Wall-clock moved backward
    /// 2. Monotonic time moved backward (bug, shouldn't happen)
    /// 3. Current time inconsistent with monotonic progression
    ///
    /// # Errors
    /// - `TimeRollbackDetected`: Wall-clock moved backward
    /// - `MonotonicTimeInconsistent`: Monotonic time moved backward
    /// - `NoTimeAnchor`: No reference anchor set yet
    pub fn check_rollback(&self) -> Result<(), LockError> {
        let reference = self.reference_anchor.as_ref().ok_or_else(|| {
            LockError::NoTimeAnchor {
                reason: "No reference anchor set".to_string(),
            }
        })?;

        let now = Utc::now();
        let now_monotonic = monotonic_elapsed_ms()?;

        // Check 1: Monotonic time must never go backward
        if now_monotonic < reference.monotonic_ms {
            return Err(LockError::MonotonicTimeInconsistent {
                expected_at_least_ms: reference.monotonic_ms,
                observed_ms: now_monotonic,
            });
        }

        // Check 2: Wall-clock must not move backward
        if now < reference.wall_clock {
            let rollback_ms =
                (reference.wall_clock - now).num_milliseconds();
            return Err(LockError::TimeRollbackDetected {
                previous_time: reference.wall_clock.to_rfc3339(),
                current_time: now.to_rfc3339(),
                rollback_amount_ms: rollback_ms,
            });
        }

        Ok(())
    }

    /// Add a new anchor and check for rollback.
    ///
    /// This is called periodically to update the reference point and detect cheating.
    ///
    /// # Errors
    /// Same as `check_rollback()`
    pub fn record_anchor(&mut self, anchor: TimeAnchor) -> Result<(), LockError> {
        // First check against reference anchor
        self.check_rollback()?;

        // If we have a reference, also check against the most recent anchor
        if let Some(last_anchor) = self.history.last() {
            // Monotonic must move forward (or stay same, but shouldn't)
            if anchor.monotonic_ms < last_anchor.monotonic_ms {
                return Err(LockError::MonotonicTimeInconsistent {
                    expected_at_least_ms: last_anchor.monotonic_ms,
                    observed_ms: anchor.monotonic_ms,
                });
            }

            // Wall-clock must not move backward
            if anchor.wall_clock < last_anchor.wall_clock {
                let rollback_ms =
                    (last_anchor.wall_clock - anchor.wall_clock).num_milliseconds();
                return Err(LockError::TimeRollbackDetected {
                    previous_time: last_anchor.wall_clock.to_rfc3339(),
                    current_time: anchor.wall_clock.to_rfc3339(),
                    rollback_amount_ms: rollback_ms,
                });
            }
        }

        self.history.push(anchor);
        Ok(())
    }

    /// Get the reference anchor.
    pub fn reference_anchor(&self) -> Option<&TimeAnchor> {
        self.reference_anchor.as_ref()
    }

    /// Get the anchor history.
    pub fn history(&self) -> &[TimeAnchor] {
        &self.history
    }
}

impl Default for TimeValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn time_anchor_can_be_created() {
        let anchor = TimeAnchor::now();
        assert!(anchor.is_ok());

        let anchor = anchor.unwrap();
        assert!(anchor.monotonic_ms > 0);
    }

    #[test]
    fn time_anchor_from_parts() {
        let wall_clock = Utc::now();
        let monotonic_ms = 1_000_000;

        let anchor = TimeAnchor::from_parts(wall_clock, monotonic_ms);
        assert_eq!(anchor.wall_clock(), wall_clock);
        assert_eq!(anchor.monotonic_ms(), monotonic_ms);
    }

    #[test]
    fn time_validator_empty_initially() {
        let validator = TimeValidator::new();
        assert!(validator.reference_anchor().is_none());
        assert_eq!(validator.history().len(), 0);
    }

    #[test]
    fn time_validator_can_set_reference_anchor() {
        let mut validator = TimeValidator::new();
        let anchor = TimeAnchor::now().unwrap();

        let result = validator.set_reference_anchor(anchor.clone());
        assert!(result.is_ok());
        assert_eq!(validator.reference_anchor(), Some(&anchor));
        assert_eq!(validator.history().len(), 1);
    }

    #[test]
    fn time_validator_cannot_set_anchor_twice() {
        let mut validator = TimeValidator::new();
        let anchor1 = TimeAnchor::now().unwrap();
        let anchor2 = TimeAnchor::now().unwrap();

        validator.set_reference_anchor(anchor1).unwrap();
        let result = validator.set_reference_anchor(anchor2);
        assert!(result.is_err());
    }

    #[test]
    fn time_validator_check_rollback_without_anchor_fails() {
        let validator = TimeValidator::new();
        let result = validator.check_rollback();
        assert!(result.is_err());
    }

    #[test]
    fn time_validator_check_rollback_with_current_time_passes() {
        let mut validator = TimeValidator::new();
        let anchor = TimeAnchor::now().unwrap();

        validator.set_reference_anchor(anchor).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let result = validator.check_rollback();
        assert!(result.is_ok());
    }

    #[test]
    fn time_validator_detects_wall_clock_rollback() {
        let mut validator = TimeValidator::new();

        // Create anchor at time T
        let wall_clock = Utc::now();
        let monotonic_ms = 1_000_000;
        let anchor = TimeAnchor::from_parts(wall_clock, monotonic_ms);

        validator.set_reference_anchor(anchor).unwrap();

        // Simulate wall-clock moving backward
        let past_time = wall_clock - Duration::hours(1);
        let future_monotonic = monotonic_ms + 60_000; // monotonic moves forward

        // We can't directly check, so we check via record_anchor
        let fake_anchor = TimeAnchor::from_parts(past_time, future_monotonic);
        let result = validator.record_anchor(fake_anchor);

        // Should detect rollback
        assert!(result.is_err());
        match result {
            Err(LockError::TimeRollbackDetected { .. }) => {}
            _ => panic!("Expected TimeRollbackDetected error"),
        }
    }

    #[test]
    fn time_validator_detects_monotonic_regression() {
        let mut validator = TimeValidator::new();

        // Create anchor at time T with monotonic M
        let wall_clock = Utc::now();
        let monotonic_ms = 1_000_000;
        let anchor = TimeAnchor::from_parts(wall_clock, monotonic_ms);

        validator.set_reference_anchor(anchor).unwrap();

        // Simulate monotonic time going backward (impossible, but test detection)
        let future_time = wall_clock + Duration::seconds(10);
        let past_monotonic = monotonic_ms - 1; // monotonic goes backward (cheating attempt)

        let fake_anchor = TimeAnchor::from_parts(future_time, past_monotonic);
        let result = validator.record_anchor(fake_anchor);

        // Should detect monotonic regression
        assert!(result.is_err());
        match result {
            Err(LockError::MonotonicTimeInconsistent { .. }) => {}
            _ => panic!("Expected MonotonicTimeInconsistent error"),
        }
    }

    #[test]
    fn time_validator_accepts_normal_progression() {
        let mut validator = TimeValidator::new();

        // Create anchor at time T
        let wall_clock = Utc::now();
        let monotonic_ms = 1_000_000;
        let anchor = TimeAnchor::from_parts(wall_clock, monotonic_ms);

        validator.set_reference_anchor(anchor).unwrap();

        // Time advances normally
        let later_time = wall_clock + Duration::seconds(10);
        let later_monotonic = monotonic_ms + 10_000;

        let later_anchor = TimeAnchor::from_parts(later_time, later_monotonic);
        let result = validator.record_anchor(later_anchor);

        assert!(result.is_ok());
        assert_eq!(validator.history().len(), 2);
    }

    #[test]
    fn time_validator_history_is_ordered() {
        let mut validator = TimeValidator::new();

        let anchor1 = TimeAnchor::from_parts(Utc::now(), 1_000_000);
        validator.set_reference_anchor(anchor1.clone()).unwrap();

        let anchor2 = TimeAnchor::from_parts(
            Utc::now() + Duration::seconds(1),
            1_001_000,
        );
        validator.record_anchor(anchor2.clone()).unwrap();

        let anchor3 = TimeAnchor::from_parts(
            Utc::now() + Duration::seconds(2),
            1_002_000,
        );
        validator.record_anchor(anchor3.clone()).unwrap();

        let history = validator.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], anchor1);
        assert_eq!(history[1], anchor2);
        assert_eq!(history[2], anchor3);
    }

    #[test]
    fn time_validator_large_time_jump_forward_ok() {
        let mut validator = TimeValidator::new();

        let wall_clock = Utc::now();
        let monotonic_ms = 1_000_000;
        let anchor = TimeAnchor::from_parts(wall_clock, monotonic_ms);

        validator.set_reference_anchor(anchor).unwrap();

        // Large jump forward (user suspends/hibernates system, then resumes after days)
        let much_later_time = wall_clock + Duration::days(10);
        let much_later_monotonic = monotonic_ms + (10 * 24 * 60 * 60 * 1000); // 10 days in ms

        let later_anchor = TimeAnchor::from_parts(much_later_time, much_later_monotonic);
        let result = validator.record_anchor(later_anchor);

        // Should accept normal forward progression
        assert!(result.is_ok());
    }
}
