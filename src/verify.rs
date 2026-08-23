//! V-13 offline integrity verification: re-hash installed trees against the
//! ledger's per-entry tree digests. No network, no kernel — pure disk +
//! `installed.json`. Exit contract: all OK → 0, any TAMPERED → 3, only
//! MISSING/UNKNOWN BASELINE → 1.

use std::path::Path;

use crate::dropin::plugin_dir;
use crate::error::VynmError;
use crate::installer::tree_digest;
use crate::state::{load_state, InstalledEntry};

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyStatus {
    Ok,
    Tampered {
        expected: String,
        actual: String,
    },
    Missing(String),
    /// pre-v3 ledger entry — no digest was ever recorded for this install
    UnknownBaseline,
}

pub struct EntryReport {
    pub slug: String,
    pub status: VerifyStatus,
}

/// pure so tests can pin every branch without env setup
pub fn verify_entry(entry: &InstalledEntry, plugin_base: &Path) -> VerifyStatus {
    let Some(expected) = &entry.tree_sha256 else {
        return VerifyStatus::UnknownBaseline;
    };
    let dir = plugin_base.join(&entry.slug);
    if !dir.is_dir() {
        return VerifyStatus::Missing(dir.display().to_string());
    }
    match tree_digest(&dir) {
        // unreadable mid-walk counts as tampering: the tree cannot be proven
        // intact, and fail-closed is the only safe answer for an integrity gate
        Ok(actual) if actual == *expected => VerifyStatus::Ok,
        Ok(actual) => VerifyStatus::Tampered {
            expected: expected.clone(),
            actual,
        },
        Err(e) => VerifyStatus::Tampered {
            expected: expected.clone(),
            actual: format!("<unreadable: {e}>"),
        },
    }
}

fn label(status: &VerifyStatus) -> String {
    match status {
        VerifyStatus::Ok => "OK".into(),
        VerifyStatus::Tampered { expected, actual } => {
            format!("TAMPERED (expected {expected}, actual {actual})")
        }
        VerifyStatus::Missing(dir) => format!("MISSING ({dir})"),
        VerifyStatus::UnknownBaseline => {
            "UNKNOWN BASELINE (pre-v3 install — reinstall to enable verification)".into()
        }
    }
}

pub fn verify_cmd(tmp_dir: &Path, slug: Option<&str>) -> Result<(), VynmError> {
    let state = load_state(tmp_dir);
    let reports: Vec<EntryReport> = match slug {
        Some(s) => match state.get(s) {
            Some(entry) => vec![EntryReport {
                slug: entry.slug.clone(),
                status: verify_entry(entry, &plugin_dir(tmp_dir)),
            }],
            None => {
                let installed: Vec<&str> = state.entries.iter().map(|e| e.slug.as_str()).collect();
                return Err(VynmError::InvalidInput(if installed.is_empty() {
                    format!("unknown plugin '{s}' — nothing is installed")
                } else {
                    format!(
                        "unknown plugin '{s}' — installed plugins: {}",
                        installed.join(", ")
                    )
                }));
            }
        },
        None => {
            let mut entries = state.entries.clone();
            entries.sort_by(|a, b| a.slug.cmp(&b.slug));
            entries
                .iter()
                .map(|e| EntryReport {
                    slug: e.slug.clone(),
                    status: verify_entry(e, &plugin_dir(tmp_dir)),
                })
                .collect()
        }
    };

    if reports.is_empty() {
        println!("no plugins installed");
        return Ok(());
    }

    println!("{:<24} STATUS", "SLUG");
    for r in &reports {
        println!("{:<24} {}", r.slug, label(&r.status));
    }
    let ok = reports
        .iter()
        .filter(|r| r.status == VerifyStatus::Ok)
        .count();
    let tampered = reports
        .iter()
        .filter(|r| matches!(r.status, VerifyStatus::Tampered { .. }))
        .count();
    let missing = reports
        .iter()
        .filter(|r| matches!(r.status, VerifyStatus::Missing(_)))
        .count();
    let unknown = reports
        .iter()
        .filter(|r| r.status == VerifyStatus::UnknownBaseline)
        .count();
    println!("{ok} ok, {tampered} tampered, {missing} missing, {unknown} unknown baseline");

    if tampered > 0 {
        // wording is load-bearing: "integrity check failed" maps to the
        // verification exit code in cli::exit_code
        Err(VynmError::Internal(format!(
            "integrity check failed: {tampered} of {} installed trees tampered",
            reports.len()
        )))
    } else if missing + unknown > 0 {
        Err(VynmError::Internal(format!(
            "{} of {} installs unverifiable (missing or pre-v3 baseline)",
            missing + unknown,
            reports.len()
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
