//! V-06 acceptance tests: exit-code contract, --source validation, and the
//! plugins.d path round-trip against the kernel's resolution logic.

use std::fs;
use std::path::Path;

use tempfile::tempdir;
use vynkor_manager::cli::{
    exit_code, resolve_plugins_dir, Ctx, EXIT_FAILURE, EXIT_NETWORK, EXIT_OK, EXIT_VERIFICATION,
};
use vynkor_manager::source::official_source;
use vynkor_manager::VynmError;

// ── exit codes (scripting contract) ─────────────────────────────────────────

#[test]
fn network_errors_map_to_exit_2() {
    let e = VynmError::Network("fetch registry: timeout".into());
    assert_eq!(exit_code(&e), EXIT_NETWORK);
}

#[test]
fn verification_failures_map_to_exit_3() {
    // canonical wording carried by the ported security refusals
    for msg in [
        "Plugin 'x' failed signature verification — ...",
        "Archive integrity check failed. Expected a, got b.",
        "Plugin 'x' v1 is revoked by the maintainer. Aborting — do not install.",
        "Malformed archive: decompressed size exceeds max 1 bytes. Aborting.",
        "Malformed archive: path traversal detected in entry '../a'. Aborting.",
    ] {
        let e = VynmError::Internal(msg.into());
        assert_eq!(exit_code(&e), EXIT_VERIFICATION, "msg: {msg}");
    }
}

#[test]
fn everything_else_maps_to_exit_1() {
    assert_eq!(
        exit_code(&VynmError::Internal("not found".into())),
        EXIT_FAILURE
    );
    assert_eq!(
        exit_code(&VynmError::InvalidInput("invalid slug".into())),
        EXIT_FAILURE
    );
    assert_eq!(
        exit_code(&VynmError::Io(std::io::ErrorKind::NotFound.into())),
        EXIT_FAILURE
    );
    let _ = EXIT_OK; // 0 is produced by Ok(()) paths, not by errors
}

// ── §6.5 --source validation ────────────────────────────────────────────────

#[test]
fn source_validation_accepts_configured_and_rejects_unknown() {
    let ctx = Ctx {
        plugins_dir: Path::new("/tmp").into(),
        source: official_source(),
        tmp_dir: Path::new("/tmp").into(),
    };

    // absent flag → configured source
    let s = ctx.resolve_source(None).unwrap();
    assert_eq!(s.name, "official");

    // exact configured name → ok
    assert!(ctx.resolve_source(Some("official")).is_ok());

    // anything else → rejected, listing what IS configured
    let err = ctx.resolve_source(Some("corp")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown source 'corp'"), "unexpected: {msg}");
    assert!(
        msg.contains("configured sources: official"),
        "unexpected: {msg}"
    );
}

// ── plugins.d round-trip (kernel-side logic ported verbatim) ────────────────

#[test]
fn plugins_dir_defaults_to_config_dir_plugins_d() {
    assert_eq!(
        resolve_plugins_dir("/etc/vyn/config.yaml", None),
        Path::new("/etc/vyn/plugins.d")
    );
    // bare filename (no parent) → relative fallback
    assert_eq!(
        resolve_plugins_dir("config.yaml", None),
        Path::new("plugins.d")
    );
}

#[test]
fn explicit_plugins_dir_key_wins_over_derivation() {
    assert_eq!(
        resolve_plugins_dir("/etc/vyn/config.yaml", Some(Path::new("/srv/plug"))),
        Path::new("/srv/plug")
    );
}

// full round trip: a kernel-style config.yaml on disk resolves through
// Ctx::load exactly like the kernel's own load_config would
#[test]
fn config_round_trip_with_kernel_style_yaml() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("config.yaml"),
        "port: 8080\njwt_secret: change-me-in-production\nplugins_dir: /custom/dropins\nregistry_url: https://registries.corp.internal/registry.json\n",
    )
    .unwrap();

    let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
    // explicit key wins over <dir>/plugins.d
    assert_eq!(ctx.plugins_dir, Path::new("/custom/dropins"));
    // single-key back-compat maps onto the official entry
    assert_eq!(
        ctx.source.url,
        "https://registries.corp.internal/registry.json"
    );
    assert_eq!(ctx.source.name, "official");
}

#[test]
fn missing_config_file_yields_pure_defaults() {
    let ctx = Ctx::load("/nonexistent/vynm/config.yaml").unwrap();
    assert_eq!(
        ctx.plugins_dir,
        resolve_plugins_dir("/nonexistent/vynm/config.yaml", None)
    );
    assert_eq!(ctx.source.name, "official");
}
