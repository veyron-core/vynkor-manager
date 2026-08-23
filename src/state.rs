use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::VynmError;

/// current on-disk schema of `installed.json`. v1 = pre-vynkor kernel ledger
/// (no `schema_version`, no per-entry `source`); v2 adds both. v3 adds the
/// per-entry tree digest (`tree_sha256`, V-13) so installed trees can be
/// verified offline — the archive `sha256` can't re-hash an extracted tree.
/// reads of older files are migrated in memory — missing fields default,
/// never error.
pub const LEDGER_SCHEMA_VERSION: u32 = 3;

/// origin source name recorded for installs made before multi-source existed.
pub const DEFAULT_SOURCE: &str = "official";

fn default_source() -> String {
    DEFAULT_SOURCE.to_string()
}

/// One recorded install in `installed.json` — the explicit state store that
/// replaces filesystem-sniffing `~/.local/lib/vyn/plugins/<slug>` (R10-02).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledEntry {
    pub slug: String,
    pub version: String,
    /// sha256 of the archive that produced this install.
    pub sha256: String,
    /// Unix epoch seconds when the install completed.
    pub installed_at: u64,
    /// Registry URL this plugin was installed from.
    pub source_url: String,
    /// §6.2 origin source name (`official`, or a configured source name).
    /// updates/reinstalls resolve against it once multiple sources exist;
    /// pre-v2 ledgers read back as `official`. V-15: `local` marks an
    /// archive-mode install — V-12 `update` must treat it as not-updatable
    /// via registries.
    #[serde(default = "default_source")]
    pub source: String,
    /// V-13 digest of the INSTALLED TREE at install time (`installer::
    /// tree_digest`) — the archive `sha256` above can't re-hash an extracted
    /// tree offline. None = pre-v3 entry, verification reports unknown
    /// baseline instead of guessing.
    #[serde(default)]
    pub tree_sha256: Option<String>,
}

/// The on-disk shape of `installed.json`. Serialized with pretty JSON so an
/// operator can read it; unknown future fields are ignored by serde.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstalledState {
    /// 0 = absent (pre-v2 file) → normalized up by `load_state`.
    #[serde(default)]
    pub schema_version: u32,
    pub entries: Vec<InstalledEntry>,
}

impl InstalledState {
    pub fn get(&self, slug: &str) -> Option<&InstalledEntry> {
        self.entries.iter().find(|e| e.slug == slug)
    }

    /// Insert or replace the entry for `slug` — one record per plugin.
    fn upsert(&mut self, entry: InstalledEntry) {
        match self.entries.iter_mut().find(|e| e.slug == entry.slug) {
            Some(slot) => *slot = entry,
            None => self.entries.push(entry),
        }
    }

    /// Remove the entry for `slug`, returning it if it existed.
    fn remove(&mut self, slug: &str) -> Option<InstalledEntry> {
        let idx = self.entries.iter().position(|e| e.slug == slug)?;
        Some(self.entries.remove(idx))
    }
}

/// Directory holding `installed.json`. `VYNM_STATE_DIR` overrides for
/// relocatable setups and tests; otherwise the XDG data dir, mirroring how
/// `plugin_dir()` resolves its override then `$HOME/.local/lib`. (The kernel
/// equivalent is `VEYRON_STATE_DIR`; the manager owns its namespace.)
/// `tmp_dir` is the fallback base when `$HOME` is unset (same convention as
/// `plugin_dir`/registry cache — never the shared `/tmp`, AUDIT M-09).
/// §6.6: pub — stage-3 config layering must not fork path logic.
pub fn state_dir(tmp_dir: &Path) -> PathBuf {
    std::env::var("VYNM_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("XDG_DATA_HOME")
                .map(|d| PathBuf::from(d).join("vyn"))
                .unwrap_or_else(|_| dirs_home(tmp_dir).join(".local").join("share").join("vyn"))
        })
}

/// Full path of the ledger file. §6.6: pub alongside `state_dir` for the
/// same reason — one path logic, layered later, never forked.
pub fn state_path(tmp_dir: &Path) -> PathBuf {
    state_dir(tmp_dir).join("installed.json")
}

fn dirs_home(tmp_dir: &Path) -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| tmp_dir.to_path_buf())
}

/// Read the install ledger. A missing file is an empty state; a corrupt file
/// is logged and treated as empty — a broken ledger must never block the CLI
/// (it self-heals on the next install/remove). Pre-v2 ledgers read cleanly:
/// missing `schema_version`/`source` default in, then the version normalizes
/// so the next save persists the current schema.
pub fn load_state(tmp_dir: &Path) -> InstalledState {
    let path = state_path(tmp_dir);
    match fs::read_to_string(&path) {
        Ok(data) => {
            let mut state: InstalledState = serde_json::from_str(&data).unwrap_or_else(|e| {
                tracing::warn!(
                    "corrupt installed state at {}, starting empty: {e}",
                    path.display()
                );
                InstalledState::default()
            });
            if state.schema_version < LEDGER_SCHEMA_VERSION {
                // per-field defaults already applied by serde (source →
                // "official"); just stamp the version so the migration sticks.
                state.schema_version = LEDGER_SCHEMA_VERSION;
            }
            state
        }
        Err(_) => InstalledState::default(),
    }
}

/// Write the ledger atomically (temp + rename in the same dir), so a crash
/// mid-write can never leave a half-written `installed.json`. Every write
/// carries the current schema version — callers can't persist a stale one.
pub fn save_state(tmp_dir: &Path, state: &InstalledState) -> Result<(), VynmError> {
    let dir = state_dir(tmp_dir);
    fs::create_dir_all(&dir).map_err(VynmError::Io)?;
    let path = dir.join("installed.json");
    let tmp = dir.join(".installed.json.tmp");
    let mut out = state.clone();
    out.schema_version = LEDGER_SCHEMA_VERSION;
    let json = serde_json::to_string_pretty(&out)
        .map_err(|e| VynmError::Cache(format!("serialize installed state: {e}")))?;
    fs::write(&tmp, json).map_err(VynmError::Io)?;
    fs::rename(&tmp, &path).map_err(VynmError::Io)?;
    Ok(())
}

/// Record a completed install (upsert by slug). Best-effort callers may treat
/// an error as fatal — a plugin on disk but untracked is exactly the drift
/// this store exists to prevent.
pub fn record_install(tmp_dir: &Path, entry: InstalledEntry) -> Result<(), VynmError> {
    let mut state = load_state(tmp_dir);
    state.upsert(entry);
    save_state(tmp_dir, &state)
}

/// Drop the entry for `slug`, returning it if it was tracked.
pub fn remove_record(tmp_dir: &Path, slug: &str) -> Result<Option<InstalledEntry>, VynmError> {
    let mut state = load_state(tmp_dir);
    let removed = state.remove(slug);
    if removed.is_some() {
        save_state(tmp_dir, &state)?;
    }
    Ok(removed)
}

/// Format a unix-epoch timestamp as `YYYY-MM-DD HH:MM:SS` (UTC), dependency-
/// free — chrono would be overkill for one column in the CLI table.
pub fn format_ts(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;

    // civil-from-days (Howard Hinnant's algorithm) — valid for the whole
    // i64 day range, plenty for a 64-bit epoch.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}
