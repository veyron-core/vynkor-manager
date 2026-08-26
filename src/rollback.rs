//! `vynm rollback <slug>`: restore the previous installed version kept as
//! `<slug>.prev` by the install pipeline, swapping current ↔ previous trees
//! and ledger records symmetrically (re-running rolls forward again).
//!
//! Roadmap parked item: the install pipeline's `.bak` mechanism was "half of
//! it" — the swap already renamed the old tree aside, then threw it away.
//! `installer::commit_staged` now KEEPS that tree as `<slug>.prev` and records
//! a flat [`PreviousInstall`](crate::state::PreviousInstall) on the ledger, so
//! this command can restore it.
//!
//! The swap is symmetric by deliberate decision: the demoted current record
//! becomes the new `previous` and the restored previous becomes current, so
//! running rollback TWICE toggles back to the version you rolled away from.
//! There is exactly one hop — no history stack, no nested `previous`.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dropin::plugin_dir;
use crate::error::VynmError;
use crate::installer::tree_digest;
use crate::state::{load_state, record_install, InstalledEntry, PreviousInstall};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Restore the previous installed version of `slug` (the `<slug>.prev` tree)
/// as the current version via a symmetric swap of trees and ledger records.
pub fn run(tmp_dir: &Path, slug: &str) -> Result<(), VynmError> {
    let state = load_state(tmp_dir);
    let entry = state
        .get(slug)
        .ok_or_else(|| VynmError::PluginNotFound(slug.to_string()))?
        .clone();

    let prev = entry.previous.clone().ok_or_else(|| {
        VynmError::InvalidInput(format!(
            "'{slug}' has no previous version to roll back to — install/update over it first"
        ))
    })?;

    let base = plugin_dir(tmp_dir);
    let dest = base.join(slug);
    let prev_dir = base.join(format!("{slug}.prev"));

    if !prev_dir.is_dir() {
        return Err(VynmError::InvalidInput(format!(
            "backup directory {} for '{slug}' is missing (deleted manually?); reinstall the \
             old version to roll back",
            prev_dir.display()
        )));
    }

    // Integrity gate BEFORE any swap: the previous tree must hash to the
    // digest recorded when it was demoted. A stored None (pre-v3) is
    // tolerated — nothing to compare, proceed. A mismatch is a tamper refusal
    // (exit-3 class), consistent with the V-13 verify policy.
    if let Some(expected) = &prev.tree_sha256 {
        let actual = tree_digest(&prev_dir)?;
        if &actual != expected {
            return Err(VynmError::Verification(format!(
                "backup for '{slug}' failed integrity check — expected {expected}, got \
                 {actual}; refusing to roll back"
            )));
        }
    }

    // Symmetric atomic-ish swap: dest → rb-tmp, prev → dest, rb-tmp → prev.
    // On any rename failure, roll back the completed renames so the plugin is
    // never left half-swapped.
    let rb_tmp = base.join(format!("{slug}.rb-tmp"));
    let _ = fs::remove_dir_all(&rb_tmp);

    let dest_existed = dest.exists();
    if dest_existed {
        if let Err(e) = fs::rename(&dest, &rb_tmp) {
            let _ = fs::remove_dir_all(&rb_tmp);
            return Err(VynmError::Io(e));
        }
    }

    if let Err(e) = fs::rename(&prev_dir, &dest) {
        if dest_existed {
            let _ = fs::rename(&rb_tmp, &dest);
        }
        return Err(VynmError::Io(e));
    }

    if dest_existed {
        if let Err(e) = fs::rename(&rb_tmp, &prev_dir) {
            let _ = fs::rename(&dest, &prev_dir);
            let _ = fs::rename(&rb_tmp, &dest);
            return Err(VynmError::Io(e));
        }
    }

    // Ledger swap: the restored previous becomes current; the demoted current
    // record (flat) becomes the new `previous`, so a second rollback toggles
    // back. Rebuild FROM prev fields with slug preserved and installed_at
    // bumped to now.
    let demoted = PreviousInstall {
        version: entry.version.clone(),
        sha256: entry.sha256.clone(),
        installed_at: entry.installed_at,
        source_url: entry.source_url.clone(),
        source: entry.source.clone(),
        tree_sha256: entry.tree_sha256.clone(),
    };

    let new_current = InstalledEntry {
        slug: slug.to_string(),
        version: prev.version.clone(),
        sha256: prev.sha256.clone(),
        installed_at: now_secs(),
        source_url: prev.source_url.clone(),
        source: prev.source.clone(),
        tree_sha256: prev.tree_sha256.clone(),
        previous: Some(demoted),
    };

    record_install(tmp_dir, new_current)?;

    println!(
        "✓ '{slug}': rolled back {} -> {}",
        entry.version, prev.version
    );
    println!("   drop-in left untouched (binary path is stable across versions)");
    println!(
        "⚠ running plugins keep executing the old binary — restart the kernel \
         (or 'vyn restart <id>') to pick up the rollback"
    );

    Ok(())
}

#[cfg(test)]
#[path = "rollback_tests.rs"]
mod tests;
