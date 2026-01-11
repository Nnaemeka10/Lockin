//! Process: Windows process detection and matching.
//!
//! Threat model:
//! - User can run app with arbitrary command-line (doesn't matter)
//! - We identify by executable path/name, not command-line
//! - Need to handle path symlinks, case-insensitivity, mapped drives
//!
//! This module provides:
//! - ProcessInfo: Immutable snapshot of running process
//! - PathNormalizer: Canonicalize Windows paths
//! - ProcessMatcher: Find running processes matching a rule
//! - ProcessQuery: Query OS for process list

use crate::error::LockError;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ============================================================================
// ProcessInfo: Immutable process snapshot
// ============================================================================

/// Immutable information about a running process.
///
/// Invariants:
/// - PID is unique at a moment in time
/// - exe_name is normalized (lowercase)
/// - exe_path is normalized (lowercase, canonical if possible)
/// - Both are immutable after creation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID (unique for running process).
    pub pid: u32,

    /// Executable name (e.g., "firefox.exe", normalized to lowercase).
    pub exe_name: String,

    /// Full executable path (normalized, lowercase if on Windows).
    pub exe_path: String,
}

impl ProcessInfo {
    /// Create a new process info.
    ///
    /// # Arguments
    /// - `pid`: Process ID
    /// - `exe_name`: Executable name (will be normalized)
    /// - `exe_path`: Full path to executable (will be normalized)
    pub fn new(pid: u32, exe_name: impl Into<String>, exe_path: impl Into<String>) -> Result<Self, LockError> {
        let exe_name = exe_name.into();
        let exe_path = exe_path.into();

        // Normalize paths
        let normalized_name = Self::normalize_name(&exe_name)?;
        let normalized_path = Self::normalize_path(&exe_path)?;

        Ok(ProcessInfo {
            pid,
            exe_name: normalized_name,
            exe_path: normalized_path,
        })
    }

    /// Normalize executable name to lowercase.
    fn normalize_name(name: &str) -> Result<String, LockError> {
        if name.trim().is_empty() {
            return Err(LockError::PathNormalizationFailed {
                path: name.to_string(),
                reason: "Executable name cannot be empty".to_string(),
            });
        }

        Ok(name.to_lowercase())
    }

    /// Normalize path to lowercase (Windows is case-insensitive).
    fn normalize_path(path: &str) -> Result<String, LockError> {
        if path.trim().is_empty() {
            return Err(LockError::PathNormalizationFailed {
                path: path.to_string(),
                reason: "Executable path cannot be empty".to_string(),
            });
        }

        // On Windows, paths are case-insensitive, so normalize to lowercase
        // In a real implementation, we'd also canonicalize symlinks via GetFinalPathNameByHandle
        Ok(path.to_lowercase())
    }

    /// Check if this process matches a target executable name.
    ///
    /// Comparison is case-insensitive (both are normalized to lowercase).
    pub fn matches(&self, target_exe_name: &str) -> bool {
        let target_normalized = target_exe_name.to_lowercase();
        self.exe_name == target_normalized
    }
}

// ============================================================================
// PathNormalizer: Utility for path handling
// ============================================================================

/// Utility for normalizing and comparing Windows paths.
pub struct PathNormalizer;

impl PathNormalizer {
    /// Normalize a path for comparison.
    ///
    /// - Converts to lowercase (Windows is case-insensitive)
    /// - Canonicalizes separators to backslash
    /// - Removes trailing slashes
    pub fn normalize(path: &str) -> String {
        let path_lower = path.to_lowercase();

        // Normalize separators to backslash (Windows standard)
        let normalized = path_lower.replace('/', "\\");

        // Remove trailing backslash (but not if it's the root)
        if normalized.len() > 3 && normalized.ends_with('\\') {
            normalized[..normalized.len() - 1].to_string()
        } else {
            normalized
        }
    }

    /// Extract filename from a path.
    ///
    /// Returns the filename component (e.g., "Firefox.exe" from "C:\\Program Files\\Firefox\\Firefox.exe").
    pub fn filename(path: &str) -> Result<String, LockError> {
        let path_obj = Path::new(path);

        path_obj
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| LockError::PathNormalizationFailed {
                path: path.to_string(),
                reason: "Could not extract filename".to_string(),
            })
            .map(|s| s.to_lowercase())
    }
}

// ============================================================================
// ProcessMatcher: Find processes matching a rule
// ============================================================================

/// Matches a target executable name against running processes.
///
/// Used by the enforcement layer to find processes to monitor.
pub struct ProcessMatcher {
    /// Target app name (e.g., "Firefox.exe").
    target_app_name: String,
}

impl ProcessMatcher {
    /// Create a new process matcher.
    pub fn new(target_app_name: impl Into<String>) -> Self {
        ProcessMatcher {
            target_app_name: target_app_name.into(),
        }
    }

    /// Check if a process matches the target.
    pub fn matches(&self, process: &ProcessInfo) -> bool {
        process.matches(&self.target_app_name)
    }

    /// Find all matching processes in a list.
    pub fn find_all<'a>(&self, processes: &'a [ProcessInfo]) -> Vec<&'a ProcessInfo> {
        processes.iter().filter(|p| self.matches(p)).collect()
    }

    /// Find first matching process (if any).
    pub fn find_first<'a>(&self, processes: &'a [ProcessInfo]) -> Option<&'a ProcessInfo> {
        processes.iter().find(|p| self.matches(p))
    }
}

// ============================================================================
// ProcessQuery: Query for running processes (mock for now)
// ============================================================================

/// Query interface for running processes.
///
/// In Phase 5, this will call Windows APIs (WMI or toolhelp) to enumerate processes.
/// For now, this is a mock that demonstrates the interface.
pub struct ProcessQuery;

impl ProcessQuery {
    /// Get list of all running processes.
    ///
    /// # Errors
    /// - `ProcessEnumerationFailed`: Could not query OS for process list
    ///
    /// # Implementation Notes
    /// Currently returns empty list (mock).
    /// Phase 5 will implement with:
    /// - Windows WMI (System.Diagnostics.Process)
    /// - Or ToolHelp API (CreateToolhelp32Snapshot)
    pub fn enumerate_all() -> Result<Vec<ProcessInfo>, LockError> {
        // Phase 5: Implement with Windows APIs
        // For now, return empty (or current process for testing)
        
        #[cfg(test)]
        {
            // In tests, we can use std::process to get current process info
            Ok(vec![])
        }

        #[cfg(not(test))]
        {
            // In production, this will call Windows APIs
            Err(LockError::ProcessEnumerationFailed {
                reason: "Process enumeration not yet implemented (Phase 5)".to_string(),
            })
        }
    }

    /// Get a specific process by PID.
    ///
    /// # Errors
    /// - `ProcessQueryFailed`: Could not read process info
    pub fn get_by_pid(_pid: u32) -> Result<Option<ProcessInfo>, LockError> {
        // Phase 5: Implement with Windows APIs
        #[cfg(test)]
        {
            Ok(None)
        }

        #[cfg(not(test))]
        {
            Err(LockError::ProcessQueryFailed {
                pid,
                reason: "Process query not yet implemented (Phase 5)".to_string(),
            })
        }
    }

    /// Find all processes matching a target executable name.
    ///
    /// # Example
    /// ```ignore
    /// let matches = ProcessQuery::find_matching("Firefox.exe")?;
    /// // Returns all running Firefox processes
    /// ```
    pub fn find_matching(target_app_name: &str) -> Result<Vec<ProcessInfo>, LockError> {
        let processes = Self::enumerate_all()?;
        let matcher = ProcessMatcher::new(target_app_name);
        Ok(matcher.find_all(&processes).into_iter().cloned().collect())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_info_creation_succeeds() {
        let info = ProcessInfo::new(1234, "Firefox.exe", "C:\\Program Files\\Firefox\\firefox.exe");
        assert!(info.is_ok());

        let info = info.unwrap();
        assert_eq!(info.pid, 1234);
        assert_eq!(info.exe_name, "firefox.exe"); // normalized to lowercase
        assert_eq!(info.exe_path, "c:\\program files\\firefox\\firefox.exe"); // normalized
    }

    #[test]
    fn process_info_normalizes_names() {
        let info = ProcessInfo::new(1, "FIREFOX.EXE", "C:\\Firefox.exe").unwrap();
        assert_eq!(info.exe_name, "firefox.exe");
        assert_eq!(info.exe_path, "c:\\firefox.exe");
    }

    #[test]
    fn process_info_rejects_empty_name() {
        let result = ProcessInfo::new(1, "", "C:\\test.exe");
        assert!(result.is_err());
    }

    #[test]
    fn process_info_rejects_empty_path() {
        let result = ProcessInfo::new(1, "test.exe", "");
        assert!(result.is_err());
    }

    #[test]
    fn process_info_matches_case_insensitive() {
        let info = ProcessInfo::new(1, "firefox.exe", "C:\\Firefox.exe").unwrap();

        assert!(info.matches("Firefox.exe"));
        assert!(info.matches("FIREFOX.EXE"));
        assert!(info.matches("firefox.exe"));
        assert!(!info.matches("chrome.exe"));
    }

    #[test]
    fn path_normalizer_converts_to_lowercase() {
        let normalized = PathNormalizer::normalize("C:\\PROGRAM FILES\\Firefox.EXE");
        assert_eq!(normalized, "c:\\program files\\firefox.exe");
    }

    #[test]
    fn path_normalizer_normalizes_separators() {
        let normalized = PathNormalizer::normalize("C:/Program Files/Firefox.exe");
        assert_eq!(normalized, "c:\\program files\\firefox.exe");
    }

    #[test]
    fn path_normalizer_removes_trailing_slash() {
        let normalized = PathNormalizer::normalize("C:\\Program Files\\");
        assert_eq!(normalized, "c:\\program files");

        // But leaves root as is
        let normalized = PathNormalizer::normalize("C:\\");
        assert_eq!(normalized, "c:\\");
    }

    #[test]
    fn path_normalizer_extracts_filename() {
        let filename = PathNormalizer::filename("C:\\Program Files\\Firefox\\firefox.exe");
        assert!(filename.is_ok());
        assert_eq!(filename.unwrap(), "firefox.exe");
    }

    #[test]
    fn path_normalizer_filename_handles_mixed_separators() {
        let filename = PathNormalizer::filename("C:/Program Files/Firefox/firefox.exe");
        assert!(filename.is_ok());
        assert_eq!(filename.unwrap(), "firefox.exe");
    }

    #[test]
    fn process_matcher_finds_matching_processes() {
        let processes = vec![
            ProcessInfo::new(1, "firefox.exe", "C:\\Firefox.exe").unwrap(),
            ProcessInfo::new(2, "chrome.exe", "C:\\Chrome.exe").unwrap(),
            ProcessInfo::new(3, "FIREFOX.EXE", "C:\\Firefox2.exe").unwrap(),
        ];

        let matcher = ProcessMatcher::new("Firefox.exe");
        let matches = matcher.find_all(&processes);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].pid, 1);
        assert_eq!(matches[1].pid, 3);
    }

    #[test]
    fn process_matcher_find_first() {
        let processes = vec![
            ProcessInfo::new(1, "chrome.exe", "C:\\Chrome.exe").unwrap(),
            ProcessInfo::new(2, "firefox.exe", "C:\\Firefox.exe").unwrap(),
        ];

        let matcher = ProcessMatcher::new("Firefox.exe");
        let first = matcher.find_first(&processes);

        assert!(first.is_some());
        assert_eq!(first.unwrap().pid, 2);
    }

    #[test]
    fn process_matcher_find_first_none() {
        let processes = vec![ProcessInfo::new(1, "chrome.exe", "C:\\Chrome.exe").unwrap()];

        let matcher = ProcessMatcher::new("Firefox.exe");
        let first = matcher.find_first(&processes);

        assert!(first.is_none());
    }

    #[test]
    fn process_query_mock_enumerate_returns_empty() {
        let result = ProcessQuery::enumerate_all();
        assert!(result.is_ok());
        let processes = result.unwrap();
        assert_eq!(processes.len(), 0); // Mock returns empty
    }

    #[test]
    fn process_info_equality() {
        let info1 = ProcessInfo::new(123, "firefox.exe", "C:\\Firefox.exe").unwrap();
        let info2 = ProcessInfo::new(123, "FIREFOX.EXE", "C:\\firefox.exe").unwrap();

        // Both normalize to same values, so should be equal
        assert_eq!(info1, info2);
    }

    #[test]
    fn process_info_hash_consistent() {
        use std::collections::HashSet;

        let info1 = ProcessInfo::new(123, "firefox.exe", "C:\\Firefox.exe").unwrap();
        let info2 = ProcessInfo::new(123, "FIREFOX.EXE", "C:\\firefox.exe").unwrap();

        let mut set = HashSet::new();
        set.insert(info1);
        set.insert(info2);

        // Should have only 1 entry (same hash, equal)
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn process_matcher_empty_list() {
        let matcher = ProcessMatcher::new("firefox.exe");
        let matches = matcher.find_all(&[]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn process_info_multiple_instances() {
        // Simulate multiple instances of same app
        let p1 = ProcessInfo::new(100, "firefox.exe", "C:\\Firefox.exe").unwrap();
        let p2 = ProcessInfo::new(101, "firefox.exe", "C:\\Firefox.exe").unwrap();
        let p3 = ProcessInfo::new(102, "firefox.exe", "C:\\Firefox.exe").unwrap();

        // All have same name/path, but different PIDs
        assert_eq!(p1.exe_name, p2.exe_name);
        assert_eq!(p1.exe_path, p2.exe_path);
        assert_ne!(p1.pid, p2.pid);
        assert_ne!(p2.pid, p3.pid);

        // Matcher should find all
        let processes = vec![p1, p2, p3];
        let matcher = ProcessMatcher::new("firefox.exe");
        let matches = matcher.find_all(&processes);

        assert_eq!(matches.len(), 3);
    }
}
