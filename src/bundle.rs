//! Air-gapped `bundle export|import` (roadmap parked item): pack installed
//! plugin trees plus a filtered `installed.json` ledger into ONE zip — zero
//! network, zero registry contact — and import such a bundle on a machine
//! that has never seen the plugins.
//!
//! Import is TRANSACTIONAL: every bundled tree is staged, its V-13
//! [`tree_digest`] checked against the bundled ledger BEFORE anything is
//! committed, and any mismatch aborts the whole import (exit-3 class) with
//! staging cleaned. Ledger entries travel verbatim — `source`/`source_url`
//! ride along so origin enforcement (V-12) keeps working after a move.

use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::ZipArchive;
use zip::ZipWriter;

use crate::dropin::{plugin_dir, write_plugin_config, DropinParams};
use crate::error::VynmError;
use crate::installer::tree_digest;
use crate::state::{
    load_state, record_install, InstalledEntry, InstalledState, LEDGER_SCHEMA_VERSION,
};
use vynkor_wire::manifest::{default_resolver, validate_manifest};

/// Zip member holding the filtered ledger inside a bundle.
pub const BUNDLE_INNER_LEDGER: &str = "installed.json";
/// Prefix under which plugin trees live inside a bundle.
pub const BUNDLE_PLUGINS_PREFIX: &str = "plugins/";

// Same caps the install pipeline enforces — a bundle is untrusted input.
const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Default)]
pub struct ImportReport {
    pub imported: Vec<String>,
    pub skipped: Vec<String>,
}

fn collect_tree_files(dir: &Path) -> Result<Vec<(String, PathBuf)>, VynmError> {
    let mut out = Vec::new();
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf)>) -> Result<(), VynmError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                // Bundles never carry symlinks — extract_zip never creates
                // them either, and tree_digest skips them.
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type()?.is_dir() {
                walk(&entry.path(), &rel, out)?;
            } else {
                out.push((rel, entry.path()));
            }
        }
        Ok(())
    }
    walk(dir, "", &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Pack installed plugins (all of them, or the requested slugs) into one
/// offline bundle zip. Returns the bundle path.
pub fn export(
    tmp_dir: &Path,
    out: Option<&Path>,
    force: bool,
    slugs: &[String],
) -> Result<PathBuf, VynmError> {
    let state = load_state(tmp_dir);
    let selected: Vec<InstalledEntry> = if slugs.is_empty() {
        let mut all = state.entries.clone();
        all.sort_by(|a, b| a.slug.cmp(&b.slug));
        if all.is_empty() {
            return Err(VynmError::InvalidInput(
                "nothing installed — no plugins to bundle".into(),
            ));
        }
        all
    } else {
        let mut picked = Vec::new();
        for s in slugs {
            match state.get(s) {
                Some(e) => picked.push(e.clone()),
                None => return Err(VynmError::PluginNotFound(s.clone())),
            }
        }
        picked.sort_by(|a, b| a.slug.cmp(&b.slug));
        picked
    };

    let out_path = out.map(Path::to_path_buf).unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("vynm-bundle.zip")
    });
    if out_path.exists() && !force {
        return Err(VynmError::InvalidInput(format!(
            "{} already exists — pass --force to replace it",
            out_path.display()
        )));
    }

    let inner_ledger = InstalledState {
        schema_version: LEDGER_SCHEMA_VERSION,
        entries: selected.clone(),
    };
    let ledger_json = serde_json::to_string_pretty(&inner_ledger)
        .map_err(|e| VynmError::Internal(format!("serialize bundle ledger: {e}")))?;

    let base = plugin_dir(tmp_dir);
    let file = fs::File::create(&out_path).map_err(VynmError::Io)?;
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file(BUNDLE_INNER_LEDGER, opts)
        .map_err(|e| VynmError::Internal(format!("zip: {e}")))?;
    zip.write_all(ledger_json.as_bytes())
        .map_err(VynmError::Io)?;

    for entry in &selected {
        let tree = base.join(&entry.slug);
        if !tree.is_dir() {
            zip.finish().ok();
            let _ = fs::remove_file(&out_path);
            return Err(VynmError::PluginNotFound(format!(
                "'{}' is tracked but its tree {} is missing — repair or remove it first",
                entry.slug,
                tree.display()
            )));
        }
        for (rel, path) in collect_tree_files(&tree)? {
            let member = format!("{BUNDLE_PLUGINS_PREFIX}{}/{rel}", entry.slug);
            // Preserve the on-disk mode: the exec bit is part of the V-13
            // tree digest, so a bundle that drops it would refuse to import.
            let mode = fs::metadata(&path)?.permissions().mode() & 0o7777;
            zip.start_file(member.as_str(), opts.unix_permissions(mode))
                .map_err(|e| VynmError::Internal(format!("zip: {e}")))?;
            let bytes = fs::read(&path)?;
            zip.write_all(&bytes).map_err(VynmError::Io)?;
        }
    }
    zip.finish()
        .map_err(|e| VynmError::Internal(format!("zip: {e}")))?;

    let size = fs::metadata(&out_path)?.len();
    println!(
        "✓ bundled {} plugin(s) → {} ({size} bytes)",
        selected.len(),
        out_path.display()
    );
    for e in &selected {
        println!("  - {}@{}", e.slug, e.version);
    }
    Ok(out_path)
}

/// Extract one plugin's members (`plugins/<slug>/…`) from the archive into
/// `dest`, enforcing traversal guards and cumulative size/count caps.
fn extract_plugin_tree(
    archive: &mut ZipArchive<Cursor<Vec<u8>>>,
    slug: &str,
    dest: &Path,
    budget: &mut (u64, usize),
) -> Result<(), VynmError> {
    let prefix = format!("{BUNDLE_PLUGINS_PREFIX}{slug}/");
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(zip_err("open member"))?;
        let Some(rel) = file
            .name()
            .strip_prefix(prefix.as_str())
            .map(str::to_string)
        else {
            continue;
        };
        if rel.is_empty() {
            continue; // dir placeholder member
        }
        let rel_path = Path::new(&rel);
        if rel_path.is_absolute() || rel.split('/').any(|c| c == "..") || rel.contains('\\') {
            return Err(VynmError::Verification(format!(
                "bundle member '{}' escapes its plugin prefix — refusing",
                file.name()
            )));
        }
        budget.0 += file.size();
        budget.1 += 1;
        if budget.0 > MAX_EXTRACTED_BYTES || budget.1 > MAX_ENTRIES {
            return Err(VynmError::InvalidInput(
                "bundle exceeds extraction limits (size/entry caps) — refusing".into(),
            ));
        }
        let target = dest.join(rel_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(VynmError::Io)?;
        }
        let mut out = fs::File::create(&target).map_err(VynmError::Io)?;
        std::io::copy(&mut file, &mut out).map_err(VynmError::Io)?;
        // Restore the stored unix mode — tree_digest treats an exec-bit
        // change as tampering, so extraction must be mode-faithful.
        if let Some(mode) = file.unix_mode() {
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                .map_err(VynmError::Io)?;
        }
    }
    Ok(())
}

fn zip_err(context: &'static str) -> impl Fn(zip::result::ZipError) -> VynmError {
    move |e| VynmError::InvalidInput(format!("{context}: {e}"))
}

/// Import a bundle produced by [`export`]: verify every tree digest against
/// the bundled ledger, then commit trees + ledger records + drop-ins.
/// Transactional — any verification failure commits nothing.
pub fn import(
    tmp_dir: &Path,
    plugins_d: &Path,
    archive_path: &Path,
    force: bool,
) -> Result<ImportReport, VynmError> {
    let meta = fs::metadata(archive_path).map_err(|_| {
        VynmError::InvalidInput(format!("'{}': no such file", archive_path.display()))
    })?;
    if meta.len() > MAX_BUNDLE_BYTES {
        return Err(VynmError::InvalidInput(format!(
            "bundle size {} exceeds max {MAX_BUNDLE_BYTES} bytes",
            meta.len()
        )));
    }
    let bytes = fs::read(archive_path).map_err(VynmError::Io)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(zip_err("read bundle zip"))?;

    let mut ledger_json = String::new();
    archive
        .by_name(BUNDLE_INNER_LEDGER)
        .map_err(|_| {
            VynmError::InvalidInput(format!(
                "bundle has no '{BUNDLE_INNER_LEDGER}' member — not a vynm bundle"
            ))
        })?
        .read_to_string(&mut ledger_json)
        .map_err(VynmError::Io)?;
    let bundled: InstalledState = serde_json::from_str(&ledger_json)
        .map_err(|e| VynmError::InvalidInput(format!("malformed bundle ledger: {e}")))?;
    if bundled.entries.is_empty() {
        return Err(VynmError::InvalidInput("bundle contains no plugins".into()));
    }

    let base = plugin_dir(tmp_dir);
    let stage_root = base.join(format!(".bundle-stage-{}", std::process::id()));
    let _ = fs::remove_dir_all(&stage_root);
    fs::create_dir_all(&stage_root).map_err(VynmError::Io)?;

    let result = commit_bundle(
        &mut archive,
        &bundled,
        tmp_dir,
        plugins_d,
        &stage_root,
        force,
    );
    // Staging is ALWAYS cleaned, success or refusal — the plugin base never
    // accumulates `.bundle-stage-*` litter.
    let _ = fs::remove_dir_all(&stage_root);
    result
}

/// The transactional core: stage → digest-check everything → commit.
/// Returns the report, or the refusal error (staging already cleaned here).
fn commit_bundle(
    archive: &mut ZipArchive<Cursor<Vec<u8>>>,
    bundled: &InstalledState,
    tmp_dir: &Path,
    plugins_d: &Path,
    stage_root: &Path,
    force: bool,
) -> Result<ImportReport, VynmError> {
    let mut report = ImportReport::default();

    // Phase 1+2 — stage every tree and verify its digest. Any failure here
    // leaves only staging behind (removed by the caller).
    let mut staged: Vec<(InstalledEntry, PathBuf)> = Vec::new();
    let mut budget = (0u64, 0usize);
    for entry in &bundled.entries {
        let stage_dir = stage_root.join(&entry.slug);
        extract_plugin_tree(archive, &entry.slug, &stage_dir, &mut budget)?;
        if !stage_dir.join("plugin.json").is_file() {
            return Err(VynmError::Verification(format!(
                "bundle plugin '{}' has no plugin.json at its root — refusing",
                entry.slug
            )));
        }
        let refreshed_digest = match &entry.tree_sha256 {
            Some(expected) => {
                let actual = tree_digest(&stage_dir)?;
                if &actual != expected {
                    return Err(VynmError::Verification(format!(
                        "bundled plugin '{}' failed integrity check — expected {expected}, \
                         got {actual}; nothing was imported",
                        entry.slug
                    )));
                }
                None
            }
            None => Some(tree_digest(&stage_dir)?), // pre-v3 tolerance: refresh
        };

        // Commit phase runs per-plugin AFTER every check below passes for it;
        // because phase 1 verified ALL trees before any rename, the whole
        // import stays atomic against tampering.
        staged.push((entry.clone(), stage_dir));
        if let Some(digest) = refreshed_digest {
            staged.last_mut().expect("just pushed").0.tree_sha256 = Some(digest);
        }
    }

    // Phase 3 — commit: swap into place, record, write drop-ins.
    let base = plugin_dir(tmp_dir);
    for (entry, stage_dir) in staged {
        let dest = base.join(&entry.slug);
        if dest.exists() {
            if !force {
                println!(
                    "⚠ '{}': already installed — skipped (pass --force to replace)",
                    entry.slug
                );
                report.skipped.push(entry.slug.clone());
                continue;
            }
            fs::remove_dir_all(&dest).map_err(VynmError::Io)?;
        }
        fs::rename(&stage_dir, &dest).map_err(VynmError::Io)?;
        record_install(tmp_dir, entry.clone())?;

        // Drop-in from the REAL parsed manifest (same trick skip_reinstall
        // uses); an operator-tuned existing drop-in is left untouched.
        let manifest = validate_manifest(&dest.join("plugin.json"), None, default_resolver)
            .map_err(|e| {
                VynmError::Internal(format!("'{}' imported but invalid: {e}", entry.slug))
            })?;
        let params = DropinParams {
            slug: &entry.slug,
            plugin_id: &manifest.plugin_id,
            binary_path: &dest.join(&manifest.binary),
            sandbox: manifest.sandbox.unwrap_or(true),
        };
        match write_plugin_config(plugins_d, &params)? {
            true => println!(
                "   drop-in written: {}/{}.yaml",
                plugins_d.display(),
                entry.slug
            ),
            false => println!(
                "   drop-in {}.yaml already exists — left untouched",
                entry.slug
            ),
        }
        println!(
            "✓ imported {}@{} (source: {})",
            entry.slug, entry.version, entry.source
        );
        report.imported.push(entry.slug.clone());
    }
    Ok(report)
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
