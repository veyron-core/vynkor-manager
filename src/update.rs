//! V-12: `vynm outdated` (report-only) + `vynm update [slug] [--force] [-y]`.
//!
//! Both commands build the SAME comparison: every ledger entry is resolved
//! against its ORIGIN source (`installed.json#source`, §6.2 origin
//! enforcement) — never a shadowing search, so `bare_slug_candidates`/probe
//! stay unused here by design; only [`crate::cli::parse_target`] is shared.
//! One registry fetch per DISTINCT origin per run, cache-respecting.
//! Semver comparisons are strict via the `semver` crate — ordering is never
//! guessed when either side fails to parse.

use std::collections::BTreeMap;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::cli::{parse_target, Ctx, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_EXTRACTED_BYTES};
use crate::dropin::{plugin_dir, write_plugin_config, DropinParams};
use crate::error::VynmError;
use crate::installer::{format_permission_preview, install};
use crate::registry::{fetch_registry, RegistryEntry};
use crate::source::RegistrySource;
use crate::state::{load_state, InstalledEntry, LOCAL_SOURCE};

// ── comparison model ────────────────────────────────────────────────────────

/// What the origin-source comparison concluded for one ledger entry.
#[derive(Debug, PartialEq, Eq)]
pub enum RowKind {
    /// strictly newer version available at the origin
    Outdated,
    /// equal version, equal archive digest
    UpToDate,
    /// installed NEWER than the registry serves
    Ahead,
    /// equal version, different sha256 — rebuild detection
    Rebuild,
    /// either side unparsable semver — ordering not guessed
    Unparsable(String),
    /// ledger says `source: "local"` — never updatable via registries
    LocalSource,
    /// origin source no longer in config
    SourceGone,
    /// origin source configured but disabled
    SourceDisabled,
    /// the source's registry could not be fetched
    FetchFailed(String),
    /// fetched fine but the slug is absent from it
    NotInRegistry,
}

/// One table row / plan candidate. `available`/`available_sha256` carry the
/// chosen registry entry (max parsable semver among non-revoked matches).
#[derive(Debug)]
pub struct Row {
    pub slug: String,
    pub installed_version: String,
    pub installed_sha256: String,
    pub source_name: String,
    pub available_version: Option<String>,
    pub available_sha256: Option<String>,
    pub kind: RowKind,
}

impl Row {
    fn skip_reason(&self) -> Option<&'static str> {
        match self.kind {
            RowKind::LocalSource => Some("local installs never update"),
            _ => None,
        }
    }
}

/// A resolved-and-fetched origin source, kept so `update` executes installs
/// from exactly the document the plan was computed against.
#[derive(Debug, Clone)]
pub struct FetchedSource {
    pub source: RegistrySource,
    pub entries: Vec<RegistryEntry>,
}

/// Result of one survey run over the ledger.
#[derive(Debug, Default)]
pub struct Survey {
    /// ledger order preserved
    pub rows: Vec<Row>,
    /// distinct successfully-fetched origins, keyed by source name
    pub fetched: BTreeMap<String, FetchedSource>,
}

/// Highest non-revoked match for `slug` by strict semver.
/// Ok(None) = no match at all; Err(reason) = matches exist but none parses.
fn pick_available(
    entries: &[RegistryEntry],
    slug: &str,
) -> Result<Option<(String, String)>, String> {
    let matches: Vec<&RegistryEntry> = entries
        .iter()
        .filter(|e| (e.slug == slug || e.id == slug) && !e.is_revoked())
        .collect();
    if matches.is_empty() {
        return Ok(None);
    }
    let mut best: Option<(&RegistryEntry, semver::Version)> = None;
    let mut unparsable: Vec<String> = Vec::new();
    for e in &matches {
        match semver::Version::parse(&e.version) {
            Ok(v) => {
                if best.as_ref().is_none_or(|(_, bv)| v > *bv) {
                    best = Some((e, v));
                }
            }
            Err(_) => unparsable.push(e.version.clone()),
        }
    }
    match best {
        Some((e, _)) => Ok(Some((e.version.clone(), e.sha256.clone()))),
        None => Err(format!(
            "registry serves {} for '{slug}' but none parse as semver",
            unparsable.join(", ")
        )),
    }
}

/// Strict three-way semver classification of available vs installed.
/// Ordering is never guessed: any unparsable side yields Err.
#[derive(Debug, PartialEq, Eq)]
enum SemVerCmp {
    Older,
    Equal,
    Newer,
}

fn cmp_versions(installed: &str, available: &str) -> Result<SemVerCmp, String> {
    let inst = semver::Version::parse(installed)
        .map_err(|_| format!("installed version '{installed}' is not valid semver"))?;
    let avail = semver::Version::parse(available)
        .map_err(|_| format!("registry version '{available}' is not valid semver"))?;
    Ok(match avail.cmp(&inst) {
        std::cmp::Ordering::Greater => SemVerCmp::Newer,
        std::cmp::Ordering::Equal => SemVerCmp::Equal,
        std::cmp::Ordering::Less => SemVerCmp::Older,
    })
}

/// Survey the ledger against each entry's origin source. `scope` is the raw
/// `[<source>/]<slug>` argument of `update`; None = everything.
pub async fn survey(ctx: &Ctx, scope: Option<&str>) -> Result<Survey, VynmError> {
    let target = scope.map(parse_target);

    // an explicitly named scope source must be configured — fail loud like
    // any other unknown name rather than silently planning nothing
    if let Some(name) = target.as_ref().and_then(|t| t.source) {
        ctx.resolve_source(Some(name))?;
    }

    let state = load_state(&ctx.tmp_dir);
    let selected: Vec<&InstalledEntry> = state
        .entries
        .iter()
        .filter(|e| {
            target
                .as_ref()
                .is_none_or(|t| t.slug == e.slug && t.source.is_none_or(|name| name == e.source))
        })
        .collect();

    // group by origin (distinct sources fetch ONCE), remember first-appearance
    // order so rows come back in ledger order regardless of group iteration
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut rows: Vec<Option<Row>> = (0..selected.len()).map(|_| None).collect();
    for (i, e) in selected.iter().enumerate() {
        if !order.iter().any(|n| n == &e.source) {
            order.push(e.source.clone());
        }
        groups.entry(e.source.clone()).or_default().push(i);
    }

    let mut survey = Survey::default();
    for name in order {
        let idxs = &groups[&name];
        if name == LOCAL_SOURCE {
            for i in idxs {
                rows[*i] = Some(local_row(selected[*i]));
            }
            continue;
        }
        let Some(src) = ctx.sources.iter().find(|s| s.name == name) else {
            for i in idxs {
                rows[*i] = Some(gone_row(selected[*i]));
            }
            continue;
        };
        if !src.enabled {
            for i in idxs {
                rows[*i] = Some(disabled_row(selected[*i]));
            }
            continue;
        }
        match fetch_registry(src, false, &ctx.tmp_dir).await {
            Ok(entries) => {
                for i in idxs {
                    rows[*i] = Some(classify_row(selected[*i], &entries));
                }
                survey.fetched.insert(
                    name.clone(),
                    FetchedSource {
                        source: src.clone(),
                        entries,
                    },
                );
            }
            Err(err) => {
                for i in idxs {
                    rows[*i] = Some(fetch_failed_row(selected[*i], &err.to_string()));
                }
            }
        }
    }

    survey.rows = rows.into_iter().flatten().collect();
    Ok(survey)
}

fn base_row(e: &InstalledEntry) -> Row {
    Row {
        slug: e.slug.clone(),
        installed_version: e.version.clone(),
        installed_sha256: e.sha256.clone(),
        source_name: e.source.clone(),
        available_version: None,
        available_sha256: None,
        kind: RowKind::NotInRegistry,
    }
}

fn local_row(e: &InstalledEntry) -> Row {
    let mut r = base_row(e);
    r.kind = RowKind::LocalSource;
    r
}

fn gone_row(e: &InstalledEntry) -> Row {
    let mut r = base_row(e);
    r.kind = RowKind::SourceGone;
    r
}

fn disabled_row(e: &InstalledEntry) -> Row {
    let mut r = base_row(e);
    r.kind = RowKind::SourceDisabled;
    r
}

fn fetch_failed_row(e: &InstalledEntry, err: &str) -> Row {
    let mut r = base_row(e);
    r.kind = RowKind::FetchFailed(err.to_string());
    r
}

fn classify_row(e: &InstalledEntry, entries: &[RegistryEntry]) -> Row {
    let mut row = base_row(e);
    match pick_available(entries, &e.slug) {
        Ok(None) => row.kind = RowKind::NotInRegistry,
        Err(reason) => row.kind = RowKind::Unparsable(reason),
        Ok(Some((version, sha))) => {
            row.available_version = Some(version.clone());
            row.available_sha256 = Some(sha.clone());
            row.kind = match cmp_versions(&e.version, &version) {
                Err(reason) => RowKind::Unparsable(reason),
                Ok(SemVerCmp::Older) => RowKind::Ahead,
                Ok(SemVerCmp::Newer) => RowKind::Outdated,
                Ok(SemVerCmp::Equal) => {
                    if sha == e.sha256 {
                        RowKind::UpToDate
                    } else {
                        RowKind::Rebuild
                    }
                }
            };
        }
    }
    row
}

// ── outdated ────────────────────────────────────────────────────────────────

fn kind_label(row: &Row) -> String {
    match &row.kind {
        RowKind::Outdated => "OUTDATED".into(),
        RowKind::UpToDate => "ok".into(),
        RowKind::Ahead => "AHEAD".into(),
        RowKind::Rebuild => "REBUILD?".into(),
        RowKind::Unparsable(r) => format!("? ({r})"),
        RowKind::LocalSource => "local".into(),
        RowKind::SourceGone => format!("origin '{}' no longer configured", row.source_name),
        RowKind::SourceDisabled => format!("origin '{}' disabled", row.source_name),
        RowKind::FetchFailed(e) => format!("registry unavailable ({e})"),
        RowKind::NotInRegistry => "not in registry".into(),
    }
}

/// `vynm outdated` — report-only over ALL ledger entries, exit 0 always.
pub async fn outdated_cmd(ctx: &Ctx) -> Result<(), VynmError> {
    let survey = survey(ctx, None).await?;

    println!(
        "{:<24} {:<12} {:<12} {:<14} STATUS",
        "SLUG", "INSTALLED", "AVAILABLE", "SOURCE"
    );
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for row in &survey.rows {
        let label = kind_label(row);
        let bucket: &'static str = match row.kind {
            RowKind::Outdated => "outdated",
            RowKind::UpToDate => "up to date",
            RowKind::Ahead => "ahead",
            RowKind::Rebuild => "rebuild?",
            RowKind::Unparsable(_) | RowKind::NotInRegistry => "unresolved",
            RowKind::FetchFailed(_)
            | RowKind::SourceDisabled
            | RowKind::SourceGone
            | RowKind::LocalSource => "skipped",
        };
        *counts.entry(bucket).or_default() += 1;
        println!(
            "{:<24} {:<12} {:<12} {:<14} {}{}",
            row.slug,
            row.installed_version,
            row.available_version.as_deref().unwrap_or("-"),
            row.source_name,
            label,
            row.skip_reason()
                .map(|r| format!(" — {r}"))
                .unwrap_or_default(),
        );
    }

    let total = survey.rows.len();
    let summary = counts
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!();
    println!("{total} installed — {summary}");
    Ok(())
}

// ── update ──────────────────────────────────────────────────────────────────

const REBUILD_HINT: &str =
    "rebuild detected — same version, different digest; pass --force to reinstall";

const RESTART_HINT: &str = "⚠ running plugins keep executing the old binary — restart the kernel \
     (or 'vyn restart <id>') to pick up updates";

/// The batch confirmation decision matrix — pure mirror of the V-10 gate so
/// tests pin every branch without a TTY. ONE prompt covers the whole batch.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmMode {
    AutoYes,
    Interactive,
    NonInteractiveRefusal,
}

fn confirm_mode(explicit_yes: bool, interactive: bool) -> ConfirmMode {
    if explicit_yes {
        ConfirmMode::AutoYes
    } else if interactive {
        ConfirmMode::Interactive
    } else {
        ConfirmMode::NonInteractiveRefusal
    }
}

fn read_yes_from_stdin() -> bool {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok() && line.trim().eq_ignore_ascii_case("y")
}

/// `vynm update [slug] [--force] [-y]`. `ask` is injected for tests (prompt
/// counting); prod passes [`read_yes_from_stdin`].
pub async fn update_cmd_with_ask(
    ctx: &Ctx,
    scope: Option<&str>,
    force: bool,
    yes: bool,
    interactive: bool,
    mut ask: impl FnMut() -> bool,
) -> Result<(), VynmError> {
    let survey = survey(ctx, scope).await?;

    // strictly-newer ONLY; rebuilds warn and join the batch solely under --force
    let mut planned: Vec<&Row> = Vec::new();
    for row in &survey.rows {
        match row.kind {
            RowKind::Outdated => planned.push(row),
            RowKind::Rebuild => {
                println!(
                    "⚠ {REBUILD_HINT}: {} (installed sha {}, registry sha {})",
                    row.slug,
                    short_sha(&row.installed_sha256),
                    short_sha(row.available_sha256.as_deref().unwrap_or("")),
                );
                if force {
                    planned.push(row);
                }
            }
            _ => {}
        }
    }

    if planned.is_empty() {
        println!("everything up to date");
        return Ok(());
    }

    println!("{} update(s) planned:", planned.len());
    for row in &planned {
        println!(
            "  {}: {} → {} (via {})",
            row.slug,
            row.installed_version,
            row.available_version.as_deref().unwrap_or("?"),
            row.source_name,
        );
    }

    match confirm_mode(yes, interactive) {
        ConfirmMode::NonInteractiveRefusal => {
            return Err(VynmError::Internal(format!(
                "refusing to apply {} update(s) in a non-interactive run — pass -y/--yes to accept",
                planned.len()
            )));
        }
        ConfirmMode::Interactive => {
            print!("apply {} update(s)? [y/N] ", planned.len());
            std::io::stdout().flush().map_err(VynmError::Io)?;
            if !ask() {
                return Err(VynmError::Internal(
                    "update batch refused by operator".into(),
                ));
            }
        }
        ConfirmMode::AutoYes => {}
    }

    // the operator approved THIS batch — per-plugin V-10 gates run AutoYes,
    // previews still render informationally (no second prompt)
    let mut applied = 0usize;
    let mut failed: Vec<&str> = Vec::new();
    for row in &planned {
        let fetched = survey
            .fetched
            .get(&row.source_name)
            .expect("planned rows always come from a fetched source");

        let shelved = if row.kind == RowKind::Rebuild {
            // equal version would hit the R10-02 same-version skip — shelve
            // the current tree so the ordinary pipeline re-runs; restored on
            // failure so a botched rebuild never leaves the plugin missing
            shelve_for_rebuild(&ctx.tmp_dir, &row.slug)?
        } else {
            None
        };

        // hand install() ONLY the chosen document entry — its internal find
        // takes the first slug match, so multi-version documents must not leak
        // another version in (same discipline as V-11's resolve_pinned); the
        // FULL entry rides along so signature/digest checks see what was served
        let doc_entry = fetched
            .entries
            .iter()
            .find(|e| {
                (e.slug == row.slug || e.id == row.slug)
                    && Some(&e.version) == row.available_version.as_ref()
            })
            .expect("planned rows always reference their source's document")
            .clone();

        let result = install(
            std::slice::from_ref(&doc_entry),
            &row.slug,
            &fetched.source,
            &ctx.tmp_dir,
            MAX_ARCHIVE_BYTES,
            MAX_EXTRACTED_BYTES,
            MAX_ARCHIVE_ENTRIES,
            |manifest| {
                println!("{}", format_permission_preview(manifest));
                Ok(())
            },
        )
        .await;

        match result {
            Ok(installed) => {
                drop_shelve(shelved);
                applied += 1;
                println!(
                    "✓ {}: {} → {} (from {})",
                    row.slug, row.installed_version, installed.version, row.source_name,
                );
                // caller-side drop-in handling, identical to install_cmd:
                // create_new keeps an operator-tuned existing drop-in intact
                let params = DropinParams {
                    slug: &installed.slug,
                    plugin_id: &installed.plugin_id,
                    binary_path: &installed.binary_path,
                    sandbox: installed.sandbox_hint,
                };
                let path = ctx.plugins_dir.join(format!("{}.yaml", installed.slug));
                match write_plugin_config(&ctx.plugins_dir, &params)? {
                    true => println!("   Auto-spawn entry: {}", path.display()),
                    false => println!(
                        "   drop-in {} already exists — left untouched",
                        path.display()
                    ),
                }
            }
            Err(e) => {
                restore_shelve(shelved)?;
                failed.push(&row.slug);
                println!("✗ {}: update failed — {e}", row.slug);
            }
        }
    }

    if applied > 0 {
        println!("{RESTART_HINT}");
    }
    if !failed.is_empty() {
        return Err(VynmError::Internal(format!(
            "{} of {} update(s) failed ({})",
            failed.len(),
            planned.len(),
            failed.join(", "),
        )));
    }
    Ok(())
}

pub async fn update_cmd(
    ctx: &Ctx,
    scope: Option<&str>,
    force: bool,
    yes: bool,
) -> Result<(), VynmError> {
    update_cmd_with_ask(
        ctx,
        scope,
        force,
        yes,
        std::io::stdin().is_terminal(),
        read_yes_from_stdin,
    )
    .await
}

fn short_sha(sha: &str) -> String {
    sha.chars().take(8).collect()
}

/// rename `<plugin_dir>/<slug>` aside so the equal-version reinstall escapes
/// the R10-02 skip. Returns the shelf path when a tree was moved.
fn shelve_for_rebuild(tmp_dir: &Path, slug: &str) -> Result<Option<PathBuf>, VynmError> {
    let dest = plugin_dir(tmp_dir).join(slug);
    if !dest.exists() {
        return Ok(None);
    }
    let shelf = plugin_dir(tmp_dir).join(format!("{slug}.rebuild-bak"));
    let _ = fs::remove_dir_all(&shelf);
    fs::rename(&dest, &shelf).map_err(VynmError::Io)?;
    Ok(Some(shelf))
}

fn drop_shelve(shelf: Option<PathBuf>) {
    if let Some(shelf) = shelf {
        let _ = fs::remove_dir_all(&shelf);
    }
}

/// put a shelved pre-rebuild tree back when the fresh install failed — a
/// botched rebuild must never leave the plugin missing
fn restore_shelve(shelf: Option<PathBuf>) -> Result<(), VynmError> {
    let Some(shelf) = shelf else {
        return Ok(());
    };
    let slug = shelf
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".rebuild-bak"))
        .unwrap_or("restored-rebuild");
    let dest = match shelf.parent() {
        Some(dir) => dir.join(slug),
        None => return Ok(()),
    };
    let _ = fs::remove_dir_all(&dest);
    fs::rename(&shelf, &dest).map_err(VynmError::Io)
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
