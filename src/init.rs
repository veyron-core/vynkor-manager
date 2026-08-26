//! First-run config materialization: the OFFICIAL plugin source lives in the
//! operator's config, not in runtime code. The compiled-in
//! [`crate::source::official_source`] remains only as the last-resort
//! fallback; everything a user sees and edits starts from the TEMPLATE below,
//! written once by [`init_cmd`] (explicit) or seeded automatically the first
//! time vynm resolves its default product config path.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::VynmError;

/// The canonical product config path: `$HOME/.config/vyn/config.yaml`.
/// `None` when `$HOME` is unset (scratch/test environments never get seeded).
pub fn default_product_config_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("vyn")
            .join("config.yaml")
    })
}

/// Fully-commented starting config. The official entry is ACTIVE so a fresh
/// machine can immediately `vynm search/install`; every field is documented
/// inline because THIS FILE — not the binary — is where the download
/// location now lives.
pub const CONFIG_TEMPLATE: &str = r#"# vynkor shared product config — ONE file for the kernel (`vyn`) and the
# plugin manager (`vynm`). Each tool reads its own keys and silently ignores
# everything it does not know, so this file is safe to extend by hand.
#
# ── Where plugins come from ────────────────────────────────────────────────
# `registries:` lists every place `vynm` fetches plugins from, in priority
# order (a bare slug is searched top-down; first hit wins). The OFFICIAL
# registry is pre-filled below — change the url and every future
# `vynm install|search|update` follows YOUR value. Nothing download-related
# is hardcoded in the binary.
#
# Per-source fields:
#   name            unique id, used by `--source <name>` and `<name>/<slug>`
#   url             registry.json document URL (https:// recommended)
#   public_key      ed25519 hex key: entries must carry a valid signature;
#                   omit the whole field to run an UNSIGNED source
#   allow_unsigned  also accept http:// urls + unsigned content from this
#                   source (interactive consent still applies)
#   cache_ttl_secs  local cache lifetime in seconds (default 3600)
#   enabled         false = keep configured but skip entirely

registries:
  - name: official
    url: https://pub-6fd4e146631e43028372c95cbd2b9b42.r2.dev/registry.json
    public_key: "6ee352d706eaf5b5114a1252fb76bb8a2bfbf177b0e4c8e9c21f73b9019083ee"
    # allow_unsigned: false
    cache_ttl_secs: 3600
    enabled: true

  # Second source example — searched AFTER `official`:
  # - name: corp
  #   url: https://registry.corp.example/registry.json
  #   public_key: "<64-hex ed25519 public key>"
  #   allow_unsigned: true     # only for fully trusted networks
  #   cache_ttl_secs: 600

# Installed-plugin auto-spawn drop-ins are derived from this file's
# directory (<config dir>/plugins.d). Override only if you must:
# plugins_dir: ~/.local/lib/vyn/plugins.d

# Environment overrides beat anything above:
#   VYNM_REGISTRY_URL / VYNM_MARKETPLACE_PUBLIC_KEY / VYNM_STATE_DIR /
#   VYNM_PLUGIN_DIR

# ── kernel-side keys (parsed by `vyn`, ignored by vynm) ────────────────────
# port: 8080
# jwt_secret: "change-me-in-production"
"#;

/// `vynm init [--force]`: materialize the commented starter config.
/// Idempotent — an existing file is NEVER touched without `--force`.
/// Returns (path, whether it was written).
pub fn init_cmd(config_path: &Path, force: bool) -> Result<(PathBuf, bool), VynmError> {
    if config_path.exists() && !force {
        println!(
            "✓ {} already exists — left untouched (pass --force to regenerate)",
            config_path.display()
        );
        return Ok((config_path.to_path_buf(), false));
    }
    write_template(config_path)?;
    println!("✓ wrote {} — edit to taste", config_path.display());
    Ok((config_path.to_path_buf(), true))
}

fn write_template(path: &Path) -> Result<(), VynmError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(VynmError::Io)?;
    }
    fs::write(path, CONFIG_TEMPLATE).map_err(VynmError::Io)
}

/// Best-effort auto-seed: called by `Ctx::load` ONLY for the default product
/// path when the file is absent. A read-only HOME or any io error degrades to
/// a warning — vynm keeps working off the built-in fallback exactly as
/// before this module existed.
pub(crate) fn seed_default_config_if_missing(config_path: &Path) {
    let Some(default_path) = default_product_config_path() else {
        return;
    };
    if config_path != default_path || default_path.exists() {
        return;
    }
    if let Err(e) = write_template(&default_path) {
        tracing::warn!(
            "could not seed starter config {}: {e}; continuing with built-in defaults",
            default_path.display()
        );
    } else {
        eprintln!(
            "note: created {} with the official registry — edit to taste",
            default_path.display()
        );
    }
}
