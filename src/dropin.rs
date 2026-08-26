//! Per-plugin auto-spawn drop-ins for the kernel (`plugins.d/<slug>.yaml`):
//! write via `create_new` (O_EXCL — never follows a planted symlink), remove,
//! disable/enable by rename, and uninstall. Sandbox flags are linux-only
//! kernel semantics, so non-linux drop-ins omit the key entirely (decision
//! recorded in vynkor/docs/VYNM_PLAN.md §10).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::VynmError;
use crate::state::remove_record;

/// Base dir for installed plugins: `$VYNM_PLUGIN_DIR`, else the kernel's own
/// default `$HOME/.local/lib/vyn/plugins` — vynm manages the same tree the
/// kernel spawns from, so the fallback must stay byte-identical. `tmp_dir` is
/// the fallback base when `$HOME` is unset (never shared `/tmp`, AUDIT M-09).
pub fn plugin_dir(tmp_dir: &Path) -> PathBuf {
    std::env::var("VYNM_PLUGIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| match std::env::var("HOME") {
            Ok(home) => PathBuf::from(home).join(".local/lib/vyn/plugins"),
            Err(_) => tmp_dir.join("plugins"),
        })
}

/// Reject slugs that could escape `plugin_dir`/`plugins_dir` via path
/// traversal (`../`, `/`, `..`, empty). Applied to every path a slug is
/// joined into — the CLI target is operator input and registry slugs are
/// remote-controlled, so neither may shape a filesystem path.
fn validate_slug(slug: &str) -> Result<(), VynmError> {
    crate::validate::validate_identifier(slug, 64)
        .map_err(|e| VynmError::InvalidInput(format!("invalid slug '{slug}': {e}")))
}

/// §6.4: what the caller supplies to write a drop-in — decoupled from the
/// install flow and from any manifest/ledger type. sandbox comes from the
/// caller (the plugin's own hint once V-05 lands; operator edits afterwards).
pub struct DropinParams<'a> {
    pub slug: &'a str,
    pub plugin_id: &'a str,
    /// Absolute path of the installed executable.
    pub binary_path: &'a Path,
    pub sandbox: bool,
}

/// Render the drop-in body for a plugin (pure, no I/O). `include_sandbox`
/// selects whether the `sandbox:` line is emitted — sandbox is a linux-only
/// kernel feature, so non-linux drop-ins omit the key entirely rather than
/// write a value the kernel ignores there (§10 open question 2). Exposed for
/// format-pinning integration tests that assert the exact body text.
pub fn render_dropin(params: &DropinParams<'_>, include_sandbox: bool) -> String {
    if include_sandbox {
        format!(
            "# auto-spawn entry written by `vynm install {}` — edit to tune, remove to disable\n\
             id: {}\n\
             binary: {}\n\
             restart: on-failure\n\
             max_restarts: 5\n\
             sandbox: {}\n",
            params.slug,
            params.plugin_id,
            params.binary_path.display(),
            params.sandbox
        )
    } else {
        format!(
            "# auto-spawn entry written by `vynm install {}` — edit to tune, remove to disable\n\
             id: {}\n\
             binary: {}\n\
             restart: on-failure\n\
             max_restarts: 5\n",
            params.slug,
            params.plugin_id,
            params.binary_path.display()
        )
    }
}

/// Write a per-plugin drop-in config `plugins_dir/<slug>.yaml` (R10-01) so the
/// kernel auto-spawns the installed plugin. Returns whether the file was
/// written — an existing file (operator-tuned, or a planted symlink) is left
/// untouched. `create_new` (O_CREAT|O_EXCL) never follows a symlink, so a
/// pre-planted link cannot redirect the write onto an arbitrary target
/// (AUDIT M-09 class). Security boundary — ported verbatim.
pub fn write_plugin_config(
    plugins_dir: &Path,
    params: &DropinParams<'_>,
) -> Result<bool, VynmError> {
    validate_slug(params.slug)?;
    fs::create_dir_all(plugins_dir).map_err(VynmError::Io)?;
    let path = plugins_dir.join(format!("{}.yaml", params.slug));

    let body = render_dropin(params, cfg!(target_os = "linux"));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(body.as_bytes()).map_err(VynmError::Io)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(VynmError::Io(e)),
    }
}

/// Delete the drop-in config for `slug`. Returns whether a file was removed.
pub fn remove_plugin_config(plugins_dir: &Path, slug: &str) -> Result<bool, VynmError> {
    validate_slug(slug)?;
    let path = plugins_dir.join(format!("{slug}.yaml"));
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(VynmError::Io(e)),
    }
}

/// Outcome of an enable/disable toggle (R10-04).
#[derive(Debug, PartialEq, Eq)]
pub enum Toggle {
    /// The drop-in was renamed: enabled→disabled or disabled→enabled.
    Toggled,
    /// The requested state was already in effect.
    Already,
    /// No drop-in (active or disabled) exists for the slug.
    Missing,
}

/// Suffix a disabled drop-in carries: `plugins_dir/<slug>.yaml.disabled`.
/// The kernel's merge globs only `*.yaml`/`*.yml`, so the renamed file is
/// skipped at boot and on SIGHUP reload — the plugin stays on disk and
/// installed, but is not auto-spawned. Renaming (not deleting) preserves the
/// operator's tuning, so `enable` restores it verbatim.
const DISABLED_SUFFIX: &str = ".yaml.disabled";

fn dropin_paths(plugins_dir: &Path, slug: &str) -> (PathBuf, PathBuf) {
    (
        plugins_dir.join(format!("{slug}.yaml")),
        plugins_dir.join(format!("{slug}{DISABLED_SUFFIX}")),
    )
}

/// Disable a plugin's auto-spawn drop-in (R10-04): rename
/// `plugins_dir/<slug>.yaml` → `plugins_dir/<slug>.yaml.disabled`.
pub fn disable_plugin_config(plugins_dir: &Path, slug: &str) -> Result<Toggle, VynmError> {
    validate_slug(slug)?;
    let (active, disabled) = dropin_paths(plugins_dir, slug);
    if active.exists() && disabled.exists() {
        // fs::rename would silently clobber the disabled copy — refuse.
        return Err(VynmError::Internal(format!(
            "both {}.yaml and {}.yaml.disabled exist in {} — remove one first",
            slug,
            slug,
            plugins_dir.display()
        )));
    }
    match fs::rename(&active, &disabled) {
        Ok(()) => Ok(Toggle::Toggled),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if disabled.exists() {
                Ok(Toggle::Already)
            } else {
                Ok(Toggle::Missing)
            }
        }
        Err(e) => Err(VynmError::Io(e)),
    }
}

/// Re-enable a disabled plugin's auto-spawn drop-in (R10-04): rename
/// `plugins_dir/<slug>.yaml.disabled` → `plugins_dir/<slug>.yaml`.
pub fn enable_plugin_config(plugins_dir: &Path, slug: &str) -> Result<Toggle, VynmError> {
    validate_slug(slug)?;
    let (active, disabled) = dropin_paths(plugins_dir, slug);
    if active.exists() && disabled.exists() {
        // fs::rename would silently clobber the disabled copy — refuse.
        return Err(VynmError::Internal(format!(
            "both {}.yaml and {}.yaml.disabled exist in {} — remove one first",
            slug,
            slug,
            plugins_dir.display()
        )));
    }
    match fs::rename(&disabled, &active) {
        Ok(()) => Ok(Toggle::Toggled),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if active.exists() {
                Ok(Toggle::Already)
            } else {
                Ok(Toggle::Missing)
            }
        }
        Err(e) => Err(VynmError::Io(e)),
    }
}

/// Remove an installed plugin's directory from `plugin_dir()` and drop its
/// record from the state store. This only deletes files on disk — it does not
/// stop a running instance or edit the kernel's config; callers should stop
/// the plugin first if the kernel is running it.
pub fn uninstall(slug: &str, tmp_dir: &Path) -> Result<(), VynmError> {
    validate_slug(slug)?;
    let tracked = remove_record(tmp_dir, slug)?;
    let dest = plugin_dir(tmp_dir).join(slug);

    if dest.exists() {
        fs::remove_dir_all(&dest).map_err(VynmError::Io)?;
        println!("✓ Removed {slug} from {}/", dest.display());
        return Ok(());
    }

    // dir already gone — the state record is what makes this a success (R10-02)
    if tracked.is_some() {
        println!(
            "⚠ '{slug}' dir was already missing at {} — removed it from the install state.",
            dest.display()
        );
        return Ok(());
    }

    Err(VynmError::PluginNotFound(format!(
        "'{slug}' is not installed at {}",
        dest.display()
    )))
}
