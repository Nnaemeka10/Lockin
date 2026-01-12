//! Enforcement: Orchestrate process termination with grace periods and respawn detection.
//!
//! Threat model:
//! - Users want to run locked apps anyway
//! - Users will kill us (service) and restart the app
//! - Need to block re-spawns as well as original launches
//!
//! Design:
//! - Grace period: Warning phase before termination
//! - Respawn detection: Track process deaths and births
//! - Enforcement engine: Stateful orchestrator
//! - Structured logging: What, when, why (for forensics)
//!
//! Note: Phase 5 defines WHAT to do. Phase 6 (service) defines HOW (actual termination).

use crate::domain::LockState;
use crate::error::LockError;
use crate::process::ProcessInfo;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// EnforcementAction: What to do next
// ============================================================================

/// Action for the enforcement layer to take.
///
/// These are decisions made by the engine; the service implements them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementAction {
    /// Nothing to do (lock not active, no matching processes).
    Ignore,

    /// Send warning to UI (grace period active).
    Warn {
        /// Milliseconds until termination.
        time_remaining_ms: u64,
    },

    /// Terminate the process immediately.
    Terminate,

    /// Wait and recheck (process was terminated, checking for respawn).
    WaitForRespawn,
}

impl std::fmt::Display for EnforcementAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforcementAction::Ignore => write!(f, "Ignore"),
            EnforcementAction::Warn { time_remaining_ms } => {
                write!(f, "Warn ({}ms until termination)", time_remaining_ms)
            }
            EnforcementAction::Terminate => write!(f, "Terminate"),
            EnforcementAction::WaitForRespawn => write!(f, "Wait for respawn"),
        }
    }
}

// ============================================================================
// GracePeriod: Warning period before termination
// ============================================================================

/// Grace period configuration and state.
///
/// Invariants:
/// - Grace period duration is positive
/// - Warning phase comes before termination
/// - Cannot be modified after activation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GracePeriod {
    /// Duration of grace period (how long to warn before killing).
    duration: Duration,

    /// When the grace period started.
    started_at: Option<DateTime<Utc>>,
}

impl GracePeriod {
    /// Create a new grace period.
    ///
    /// # Arguments
    /// - `duration`: How long to warn before terminating
    ///
    /// # Errors
    /// Returns error if duration is zero or negative.
    pub fn new(duration: Duration) -> Result<Self, LockError> {
        if duration.num_milliseconds() <= 0 {
            return Err(LockError::InvalidGracePeriod {
                reason: format!(
                    "Grace period must be positive (got {:?})",
                    duration
                ),
            });
        }

        Ok(GracePeriod {
            duration,
            started_at: None,
        })
    }

    /// Activate the grace period.
    ///
    /// Once activated, the grace period cannot be modified.
    pub fn activate(&mut self) {
        if self.started_at.is_none() {
            self.started_at = Some(Utc::now());
        }
    }

    /// Check if the grace period is active.
    pub fn is_active(&self) -> bool {
        self.started_at.is_some()
    }

    /// Check if the grace period has expired.
    pub fn is_expired(&self) -> bool {
        match self.started_at {
            Some(start) => Utc::now() >= start + self.duration,
            None => false,
        }
    }

    /// Get the time remaining in the grace period.
    ///
    /// Returns `None` if grace period is not active or has expired.
    pub fn time_remaining(&self) -> Option<Duration> {
        match self.started_at {
            Some(start) => {
                let end = start + self.duration;
                let now = Utc::now();
                if now < end {
                    Some(end - now)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Get the configured duration.
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Get the start time (if activated).
    pub fn started_at(&self) -> Option<DateTime<Utc>> {
        self.started_at
    }
}

// ============================================================================
// ProcessTerminationLog: Immutable record of a termination
// ============================================================================

/// Record of a process termination event.
///
/// Used for forensics and debugging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTerminationLog {
    /// Process ID that was terminated.
    pub pid: u32,

    /// Executable name.
    pub exe_name: String,

    /// Why it was terminated (grace period expired, respawn detected, etc).
    pub reason: String,

    /// When it was terminated.
    pub terminated_at: DateTime<Utc>,
}

impl ProcessTerminationLog {
    /// Create a termination log entry.
    pub fn new(
        pid: u32,
        exe_name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        ProcessTerminationLog {
            pid,
            exe_name: exe_name.into(),
            reason: reason.into(),
            terminated_at: Utc::now(),
        }
    }
}

// ============================================================================
// RespawnDetector: Track process deaths and respawns
// ============================================================================

/// Detects if a locked process is respawning.
///
/// When we kill a locked process, we need to detect if it (or a new instance) starts again.
/// This tracker maintains a history of process identities and their state.
///
/// Invariants:
/// - PIDs are unique at a moment in time
/// - Track last-seen PIDs to detect new launches
/// - Terminate any respawn attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnDetector {
    /// Map of executable name → last-seen process info.
    last_seen: HashMap<String, ProcessInfo>,

    /// Log of terminated processes.
    termination_log: Vec<ProcessTerminationLog>,
}

impl RespawnDetector {
    /// Create a new respawn detector.
    pub fn new() -> Self {
        RespawnDetector {
            last_seen: HashMap::new(),
            termination_log: Vec::new(),
        }
    }

    /// Record a process as being monitored.
    ///
    /// Call this when a process is first detected.
    pub fn record_process(&mut self, process: ProcessInfo) {
        self.last_seen
            .insert(process.exe_name.clone(), process);
    }

    /// Check if a process is a respawn (new PID, same app name).
    ///
    /// Returns `true` if:
    /// - We've seen this app before (it was killed)
    /// - But the current process has a different PID
    /// - So it's a respawn attempt
    pub fn is_respawn(&self, process: &ProcessInfo) -> bool {
        if let Some(last) = self.last_seen.get(&process.exe_name) {
            // Different PID, same app name → respawn
            last.pid != process.pid
        } else {
            // Haven't seen this app before
            false
        }
    }

    /// Log a process termination.
    pub fn log_termination(&mut self, log: ProcessTerminationLog) {
        self.termination_log.push(log);
    }

    /// Get all terminations in the log.
    pub fn termination_log(&self) -> &[ProcessTerminationLog] {
        &self.termination_log
    }

    /// Get recent terminations (last N entries).
    pub fn recent_terminations(&self, count: usize) -> Vec<&ProcessTerminationLog> {
        self.termination_log
            .iter()
            .rev()
            .take(count)
            .collect()
    }

    /// Clear old entries (older than `cutoff_time`).
    ///
    /// Used to prevent unbounded growth of logs.
    pub fn prune_old_entries(&mut self, cutoff_time: DateTime<Utc>) {
        self.termination_log.retain(|log| log.terminated_at > cutoff_time);
    }
}

impl Default for RespawnDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EnforcementEngine: Orchestrate enforcement decisions
// ============================================================================

/// Stateful enforcer that makes decisions about what to do with locked processes.
///
/// Usage:
/// ```ignore
/// let mut engine = EnforcementEngine::new(lock_state, grace_period)?;
/// let action = engine.check_process(process)?;
/// match action {
///     EnforcementAction::Ignore => {},
///     EnforcementAction::Warn { .. } => send_warning_to_ui(),
///     EnforcementAction::Terminate => kill_process(),
///     EnforcementAction::WaitForRespawn => recheck_later(),
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementEngine {
    /// The lock that is being enforced.
    lock_state: LockState,

    /// Grace period configuration.
    grace_period: GracePeriod,

    /// Respawn detection state.
    respawn_detector: RespawnDetector,
}

impl EnforcementEngine {
    /// Create a new enforcement engine.
    ///
    /// # Arguments
    /// - `lock_state`: The active lock
    /// - `grace_period_duration`: How long to warn before killing
    ///
    /// # Errors
    /// Returns error if lock is not active or grace period is invalid.
    pub fn new(lock_state: LockState, grace_period_duration: Duration) -> Result<Self, LockError> {
        // Verify lock is active
        if !lock_state.is_active() {
            return Err(LockError::EnforcementNotApplicable {
                reason: "Lock is not active".to_string(),
            });
        }

        let grace_period = GracePeriod::new(grace_period_duration)?;

        Ok(EnforcementEngine {
            lock_state,
            grace_period,
            respawn_detector: RespawnDetector::new(),
        })
    }

    /// Make an enforcement decision for a process.
    ///
    /// # Arguments
    /// - `process`: Process to check
    ///
    /// # Returns
    /// `EnforcementAction` indicating what to do
    ///
    /// # Errors
    /// Returns error if lock is no longer active (should not happen, but defensively checked)
    pub fn check_process(&mut self, process: &ProcessInfo) -> Result<EnforcementAction, LockError> {
        // Defensive check: lock must still be active
        if !self.lock_state.is_active() {
            return Ok(EnforcementAction::Ignore);
        }

        // Check if this is a respawn (process was killed and restarted)
        if self.respawn_detector.is_respawn(process) {
            // Respawn detected → terminate immediately, no grace period
            let log = ProcessTerminationLog::new(
                process.pid,
                &process.exe_name,
                "Respawn detected (process restarted after termination)",
            );
            self.respawn_detector.log_termination(log);
            return Ok(EnforcementAction::Terminate);
        }

        // First time seeing this process (or same PID as before)
        // Activate grace period if not already active
        if !self.grace_period.is_active() {
            self.grace_period.activate();
            self.respawn_detector.record_process(process.clone());
            return Ok(EnforcementAction::Warn {
                time_remaining_ms: self.grace_period.duration().num_milliseconds() as u64,
            });
        }

        // Grace period is active, check if it's expired
        if self.grace_period.is_expired() {
            let log = ProcessTerminationLog::new(
                process.pid,
                &process.exe_name,
                "Grace period expired",
            );
            self.respawn_detector.log_termination(log);
            return Ok(EnforcementAction::Terminate);
        }

        // Grace period is still active → warn
        match self.grace_period.time_remaining() {
            Some(remaining) => Ok(EnforcementAction::Warn {
                time_remaining_ms: remaining.num_milliseconds() as u64,
            }),
            None => Ok(EnforcementAction::Terminate),
        }
    }

    /// Get the lock state.
    pub fn lock_state(&self) -> &LockState {
        &self.lock_state
    }

    /// Get the grace period.
    pub fn grace_period(&self) -> &GracePeriod {
        &self.grace_period
    }

    /// Get the respawn detector.
    pub fn respawn_detector(&self) -> &RespawnDetector {
        &self.respawn_detector
    }

    /// Get mutable respawn detector (for updating state).
    pub fn respawn_detector_mut(&mut self) -> &mut RespawnDetector {
        &mut self.respawn_detector
    }

    /// Check if enforcement should continue.
    ///
    /// Returns false if lock is no longer active (enforcement should stop).
    pub fn should_continue(&self) -> bool {
        self.lock_state.is_active()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{LockDuration, LockRule};

    fn test_lock() -> Result<LockState, LockError> {
        let duration = LockDuration::from_days(7)?;
        let rule = LockRule::new("Firefox.exe", duration)?;
        LockState::new(rule, Utc::now())
    }

    fn test_process() -> Result<ProcessInfo, LockError> {
        ProcessInfo::new(1234, "Firefox.exe", "C:\\Firefox.exe")
    }

    #[test]
    fn grace_period_creation_succeeds() {
        let grace = GracePeriod::new(Duration::seconds(30));
        assert!(grace.is_ok());
    }

    #[test]
    fn grace_period_rejects_zero_duration() {
        let grace = GracePeriod::new(Duration::seconds(0));
        assert!(grace.is_err());
    }

    #[test]
    fn grace_period_rejects_negative_duration() {
        let grace = GracePeriod::new(Duration::seconds(-1));
        assert!(grace.is_err());
    }

    #[test]
    fn grace_period_activation() {
        let mut grace = GracePeriod::new(Duration::seconds(30)).unwrap();
        assert!(!grace.is_active());

        grace.activate();
        assert!(grace.is_active());
    }

    #[test]
    fn grace_period_time_remaining_when_not_active() {
        let grace = GracePeriod::new(Duration::seconds(30)).unwrap();
        assert!(grace.time_remaining().is_none());
    }

    #[test]
    fn grace_period_time_remaining_when_active() {
        let mut grace = GracePeriod::new(Duration::seconds(30)).unwrap();
        grace.activate();

        let remaining = grace.time_remaining();
        assert!(remaining.is_some());
        let remaining = remaining.unwrap();
        // Should be close to 30 seconds
        assert!(remaining.num_seconds() >= 29 && remaining.num_seconds() <= 30);
    }

    #[test]
    fn respawn_detector_records_processes() {
        let mut detector = RespawnDetector::new();
        let process = test_process().unwrap();

        detector.record_process(process.clone());

        // Should detect respawn if PID changes
        let respawned = ProcessInfo::new(5678, "Firefox.exe", "C:\\Firefox.exe").unwrap();
        assert!(detector.is_respawn(&respawned));
    }

    #[test]
    fn respawn_detector_not_respawn_for_same_pid() {
        let mut detector = RespawnDetector::new();
        let process = test_process().unwrap();

        detector.record_process(process.clone());

        // Same PID → not a respawn
        assert!(!detector.is_respawn(&process));
    }

    #[test]
    fn respawn_detector_no_respawn_when_not_tracked() {
        let detector = RespawnDetector::new();
        let process = test_process().unwrap();

        // Never recorded → not a respawn
        assert!(!detector.is_respawn(&process));
    }

    #[test]
    fn respawn_detector_logs_terminations() {
        let mut detector = RespawnDetector::new();

        let log = ProcessTerminationLog::new(1234, "Firefox.exe", "Grace period expired");
        detector.log_termination(log);

        assert_eq!(detector.termination_log().len(), 1);
    }

    #[test]
    fn enforcement_engine_creation_requires_active_lock() {
        // Create an expired lock
        let duration = LockDuration::from_days(1).unwrap();
        let rule = LockRule::new("Firefox.exe", duration).unwrap();
        let past = Utc::now() - Duration::days(2);
        let lock = LockState::new(rule, past);

        // Should fail because lock is expired
        assert!(lock.is_err());
    }

    #[test]
    fn enforcement_engine_first_detection_warns() -> Result<(), LockError> {
        let lock = test_lock()?;
        let mut engine = EnforcementEngine::new(lock, Duration::seconds(10))?;
        let process = test_process()?;

        let action = engine.check_process(&process)?;

        match action {
            EnforcementAction::Warn { .. } => {}
            _ => panic!("Expected Warn action on first detection"),
        }

        Ok(())
    }

    #[test]
    fn enforcement_engine_respawn_terminates_immediately() -> Result<(), LockError> {
        let lock = test_lock()?;
        let mut engine = EnforcementEngine::new(lock, Duration::seconds(30))?;
        let process1 = test_process()?;

        // First detection
        engine.check_process(&process1)?;

        // Respawn (same app, different PID)
        let respawned = ProcessInfo::new(9999, "Firefox.exe", "C:\\Firefox.exe")?;
        let action = engine.check_process(&respawned)?;

        match action {
            EnforcementAction::Terminate => {}
            _ => panic!("Expected Terminate action for respawn, got {:?}", action),
        }

        Ok(())
    }

    #[test]
    fn enforcement_engine_continues_warning_during_grace_period() -> Result<(), LockError> {
        let lock = test_lock()?;
        let mut engine = EnforcementEngine::new(lock, Duration::seconds(10))?;
        let process = test_process()?;

        // First check: warn
        let action1 = engine.check_process(&process)?;
        assert!(matches!(action1, EnforcementAction::Warn { .. }));

        // Second check (still within grace period): warn again
        std::thread::sleep(std::time::Duration::from_millis(100));
        let action2 = engine.check_process(&process)?;
        assert!(matches!(action2, EnforcementAction::Warn { .. }));

        Ok(())
    }

    #[test]
    fn enforcement_engine_terminates_after_grace_period_expires() -> Result<(), LockError> {
        let lock = test_lock()?;
        let mut engine = EnforcementEngine::new(lock, Duration::milliseconds(100))?;
        let process = test_process()?;

        // First check: warn
        engine.check_process(&process)?;

        // Wait for grace period to expire
        std::thread::sleep(std::time::Duration::from_millis(150));

        // Next check: terminate
        let action = engine.check_process(&process)?;
        match action {
            EnforcementAction::Terminate => {}
            _ => panic!("Expected Terminate after grace period, got {:?}", action),
        }

        Ok(())
    }

    #[test]
    fn enforcement_engine_should_continue() -> Result<(), LockError> {
        let lock = test_lock()?;
        let engine = EnforcementEngine::new(lock, Duration::seconds(10))?;

        // Lock is active, so enforcement should continue
        assert!(engine.should_continue());

        Ok(())
    }

    #[test]
    fn process_termination_log_creation() {
        let log = ProcessTerminationLog::new(1234, "Firefox.exe", "Grace period expired");

        assert_eq!(log.pid, 1234);
        assert_eq!(log.exe_name, "Firefox.exe");
        assert_eq!(log.reason, "Grace period expired");
    }

    #[test]
    fn enforcement_action_display() {
        assert_eq!(EnforcementAction::Ignore.to_string(), "Ignore");
        assert_eq!(EnforcementAction::Terminate.to_string(), "Terminate");
        assert_eq!(
            EnforcementAction::WaitForRespawn.to_string(),
            "Wait for respawn"
        );
    }

    #[test]
    fn respawn_detector_prune_old_entries() {
        let mut detector = RespawnDetector::new();

        let now = Utc::now();
        let past = now - Duration::days(1);

        let log1 = ProcessTerminationLog {
            pid: 100,
            exe_name: "old.exe".to_string(),
            reason: "Old entry".to_string(),
            terminated_at: past,
        };

        let log2 = ProcessTerminationLog {
            pid: 200,
            exe_name: "new.exe".to_string(),
            reason: "New entry".to_string(),
            terminated_at: now,
        };

        detector.log_termination(log1);
        detector.log_termination(log2);

        // Prune entries older than 12 hours
        let cutoff = now - Duration::hours(12);
        detector.prune_old_entries(cutoff);

        // Old entry should be removed, new entry should remain
        assert_eq!(detector.termination_log().len(), 1);
        assert_eq!(detector.termination_log()[0].pid, 200);
    }

    #[test]
    fn grace_period_expired() {
        let mut grace = GracePeriod::new(Duration::milliseconds(50)).unwrap();
        grace.activate();

        assert!(!grace.is_expired());

        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(grace.is_expired());
    }
}
