//! V-06 acceptance tests: exit-code contract, --source validation, and the
//! plugins.d path round-trip against the kernel's resolution logic.

use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use tempfile::tempdir;
use vynkor_manager::cli::{
    exit_code, resolve_plugins_dir, Ctx, EXIT_FAILURE, EXIT_NETWORK, EXIT_OK, EXIT_VERIFICATION,
};
use vynkor_manager::source::{official_source, RegistrySource};
use vynkor_manager::VynmError;

// env is process-global: every Ctx::load test takes this so the VYNM_* env
// precedence tests can't leak into parallel assertions (same pattern as
// tests/installer.rs)
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

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
        sources: vec![official_source()],
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
    let _env = env_guard();
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
        ctx.sources[0].url,
        "https://registries.corp.internal/registry.json"
    );
    assert_eq!(ctx.sources[0].name, "official");
}

#[test]
fn missing_config_file_yields_pure_defaults() {
    let ctx = Ctx::load("/nonexistent/vynm/config.yaml").unwrap();
    assert_eq!(
        ctx.plugins_dir,
        resolve_plugins_dir("/nonexistent/vynm/config.yaml", None)
    );
    assert_eq!(ctx.sources[0].name, "official");
}

// ── V-09: registries list schema + precedence matrix ───────────────────────

// full-schema list entry: every optional key honored, order preserved
#[test]
fn registries_list_parses_full_schema() {
    let _env = env_guard();
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("config.yaml"),
        r#"
port: 8080  # kernel-only key, must stay tolerated
registries:
  - name: corp
    url: https://registries.corp.internal/registry.json
    public_key: aabb
    allow_unsigned: true
    cache_ttl_secs: 60
  - name: staging
    url: https://staging.example/registry.json
    enabled: false
"#,
    )
    .unwrap();

    let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
    let corp = &ctx.sources[0];
    assert_eq!(corp.name, "corp");
    assert_eq!(corp.url, "https://registries.corp.internal/registry.json");
    assert_eq!(corp.public_key.as_deref(), Some("aabb"));
    assert!(corp.allow_unsigned);
    assert_eq!(corp.cache_ttl_secs, 60);
    assert!(corp.enabled);

    let staging = &ctx.sources[1];
    assert_eq!(staging.name, "staging");
    // absent public_key = unsigned source
    assert_eq!(staging.public_key, None);
    // defaults: no consent, builtin ttl, disabled as written
    assert!(!staging.allow_unsigned);
    assert_eq!(staging.cache_ttl_secs, 3600);
    assert!(!staging.enabled);

    assert_eq!(ctx.source_names(), vec!["corp", "staging"]);
}

// duplicate names are a parse error naming both entries
#[test]
fn duplicate_registry_names_error_names_both_entries() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("config.yaml"),
        r#"
registries:
  - name: corp
    url: https://a.example/r.json
  - name: official
    url: https://b.example/r.json
  - name: corp
    url: https://c.example/r.json
"#,
    )
    .unwrap();

    let err = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate registry name 'corp'"),
        "unexpected: {msg}"
    );
    assert!(msg.contains("entries 1 and 3"), "unexpected: {msg}");
}

// precedence tier 3 > 4: when registries: is present, legacy single keys are
// ignored wholesale (they only map onto `official` without a list)
#[test]
fn registries_list_beats_legacy_single_keys() {
    let _env = env_guard();
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("config.yaml"),
        r#"
registry_url: https://legacy.example/r.json
marketplace_public_key: deadbeef
allow_unsigned: true
registries:
  - name: corp
    url: https://corp.example/r.json
"#,
    )
    .unwrap();

    let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
    assert_eq!(ctx.sources.len(), 1);
    assert_eq!(ctx.sources[0].name, "corp");
    assert_eq!(ctx.sources[0].url, "https://corp.example/r.json");
    // legacy key did NOT leak into the listed entry
    assert_eq!(ctx.sources[0].public_key, None);
    assert!(!ctx.sources[0].allow_unsigned);
}

// precedence tier 2: env overrides the configured default source in place,
// keeping its name (per-source cache + ledger identity stay stable)
#[test]
fn env_url_beats_registries_list() {
    let _env = env_guard();
    temp_env::with_var(
        "VYNM_REGISTRY_URL",
        Some("https://env.example/r.json"),
        || {
            let tmp = tempdir().unwrap();
            fs::write(
                tmp.path().join("config.yaml"),
                "registries:\n  - name: corp\n    url: https://corp.example/r.json\n",
            )
            .unwrap();
            let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
            assert_eq!(ctx.sources[0].url, "https://env.example/r.json");
            assert_eq!(ctx.sources[0].name, "corp");
            assert_eq!(ctx.sources.len(), 1);
        },
    );
}

#[test]
fn env_key_beats_configured_key() {
    let _env = env_guard();
    temp_env::with_var("VYNM_MARKETPLACE_PUBLIC_KEY", Some("envkey"), || {
        let tmp = tempdir().unwrap();
        fs::write(
                tmp.path().join("config.yaml"),
                "registries:\n  - name: corp\n    url: https://corp.example/r.json\n    public_key: cfgkey\n",
            )
            .unwrap();
        let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
        assert_eq!(ctx.sources[0].public_key.as_deref(), Some("envkey"));
    });
}

#[test]
fn env_vars_ignored_when_unset_or_empty() {
    let _env = env_guard();
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("config.yaml"),
        "registries:\n  - name: corp\n    url: https://corp.example/r.json\n",
    )
    .unwrap();
    let path = tmp.path().join("config.yaml").to_str().unwrap().to_string();
    temp_env::with_var("VYNM_REGISTRY_URL", Some(""), || {
        let ctx = Ctx::load(&path).unwrap();
        // empty env value must not blank the configured URL
        assert_eq!(ctx.sources[0].url, "https://corp.example/r.json");
    });
    temp_env::with_var_unset("VYNM_REGISTRY_URL", || {
        temp_env::with_var_unset("VYNM_MARKETPLACE_PUBLIC_KEY", || {
            let ctx = Ctx::load(&path).unwrap();
            assert_eq!(ctx.sources[0].url, "https://corp.example/r.json");
        });
    });
}

// precedence tier 4 > 5: legacy single keys map onto an official-named source
#[test]
fn legacy_single_keys_map_onto_official() {
    let _env = env_guard();
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("config.yaml"),
        r#"
registry_url: http://legacy.local/r.json
registry_cache_ttl_secs: 30
allow_unsigned: true
"#,
    )
    .unwrap();

    let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
    let s = &ctx.sources[0];
    assert_eq!(s.name, "official");
    assert_eq!(s.url, "http://legacy.local/r.json");
    assert_eq!(s.cache_ttl_secs, 30);
    assert!(s.allow_unsigned);
    // built-in pinned key survives — legacy configs keep signature checking
    assert!(s.public_key.is_some());
}

// precedence tier 5: neither list nor single keys → built-in official
#[test]
fn empty_config_yields_builtin_official() {
    let _env = env_guard();
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("config.yaml"), "port: 8080\n").unwrap();
    let ctx = Ctx::load(tmp.path().join("config.yaml").to_str().unwrap()).unwrap();
    assert_eq!(ctx.sources.len(), 1);
    assert_eq!(ctx.sources[0], official_source());
}

// --source matches ANY configured name; unknown lists every name
#[test]
fn resolve_source_matches_any_configured_name() {
    let ctx = Ctx {
        plugins_dir: Path::new("/tmp").into(),
        sources: vec![
            RegistrySource {
                name: "official".into(),
                ..official_source()
            },
            RegistrySource {
                name: "corp".into(),
                ..official_source()
            },
        ],
        tmp_dir: Path::new("/tmp").into(),
    };

    assert_eq!(ctx.resolve_source(Some("corp")).unwrap().name, "corp");
    assert_eq!(ctx.resolve_source(None).unwrap().name, "official");

    let err = ctx.resolve_source(Some("nope")).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown source 'nope'"), "unexpected: {msg}");
    assert!(
        msg.contains("configured sources: official, corp"),
        "unexpected: {msg}"
    );
}
