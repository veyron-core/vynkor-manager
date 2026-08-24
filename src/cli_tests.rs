use ed25519_dalek::SigningKey;

use super::{run, Cli, Command};
use crate::error::VynmError;

const SEED: [u8; 32] = [42; 32];

fn sign_cli(key: Option<&std::path::Path>, verify: bool) -> Cli {
    Cli {
        config: "config.yaml".into(),
        command: Command::Sign {
            key: key.map(|p| p.to_path_buf()),
            slug: "demo".into(),
            version: "1.0.0".into(),
            sha256: "abc123".into(),
            status: "stable".into(),
            archive_url: "https://example.com/demo.tar.gz".into(),
            min: "0.1.0".into(),
            max: "*".into(),
            verify,
            public_key: Some(crate::keygen::public_key_hex(&SigningKey::from_bytes(
                &SEED,
            ))),
            signature: None,
        },
    }
}

fn good_signature() -> String {
    let entry = crate::sign::entry_from_fields(
        "demo",
        "1.0.0",
        "abc123",
        "stable",
        "https://example.com/demo.tar.gz",
        "0.1.0",
        "*",
    );
    crate::sign::sign_entry(&SigningKey::from_bytes(&SEED), &entry)
}

fn set_signature(cli: &mut Cli, sig: Option<String>) {
    if let Command::Sign { signature, .. } = &mut cli.command {
        *signature = sig;
    }
}

#[tokio::test]
async fn verify_without_key_accepts_good_signature() {
    let mut cli = sign_cli(None, true);
    let sig = good_signature();
    set_signature(&mut cli, Some(sig));
    run(&cli).await.unwrap();
}

#[tokio::test]
async fn verify_without_key_rejects_tampered_with_exit_3() {
    let mut cli = sign_cli(None, true);
    let mut sig = good_signature();
    // flip one hex nibble
    let flipped = if sig.starts_with('a') { 'b' } else { 'a' };
    sig.replace_range(0..1, &flipped.to_string());
    set_signature(&mut cli, Some(sig));
    let err = run(&cli).await.unwrap_err();
    assert_eq!(super::exit_code(&err), super::EXIT_VERIFICATION);
}

#[tokio::test]
async fn sign_mode_still_requires_key() {
    let cli = sign_cli(None, false);
    let err = run(&cli).await.unwrap_err();
    assert!(
        matches!(err, VynmError::InvalidInput(ref m) if m.contains("--key")),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn verify_with_key_still_works_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k.key");
    std::fs::write(&key_path, format!("{}\n", "2a".repeat(32))).unwrap();
    let mut cli = sign_cli(Some(&key_path), true);
    set_signature(&mut cli, Some(good_signature()));
    run(&cli).await.unwrap();
}

// ── V-09 resolution-engine internals ───────────────────────────────────────

use crate::source::{official_source, RegistrySource};

fn named(name: &str, enabled: bool) -> RegistrySource {
    RegistrySource {
        name: name.into(),
        enabled,
        ..official_source()
    }
}

#[test]
fn split_target_grammar() {
    assert_eq!(
        super::split_target("corp/database"),
        Some(("corp", "database"))
    );
    // bare slugs have no slash
    assert_eq!(super::split_target("database"), None);
    // degenerate forms fall back to bare-slug handling
    assert_eq!(super::split_target("/database"), None);
    assert_eq!(super::split_target("corp/"), None);
}

// ── V-11 target grammar: `[<source>/]<slug>[@<version>]` ────────────────────

#[test]
fn parse_target_grammar() {
    use super::Target;
    assert_eq!(
        super::parse_target("database@0.1.0"),
        Target {
            source: None,
            slug: "database",
            version: Some("0.1.0")
        }
    );
    assert_eq!(
        super::parse_target("corp/database@0.1.0"),
        Target {
            source: Some("corp"),
            slug: "database",
            version: Some("0.1.0")
        }
    );
    assert_eq!(
        super::parse_target("database"),
        Target {
            source: None,
            slug: "database",
            version: None
        }
    );
    assert_eq!(
        super::parse_target("database"),
        super::parse_target("database")
    );
}

#[test]
fn parse_target_degenerate_pins_fall_back_to_bare_slug() {
    let t = super::parse_target("database@");
    assert_eq!(t.slug, "database@");
    assert_eq!(t.version, None);
    let t = super::parse_target("@1.0.0");
    assert_eq!(t.slug, "@1.0.0");
    assert_eq!(t.version, None);
}

#[test]
fn bare_slug_candidates_origin_first_then_listed_order() {
    let sources = [named("a", true), named("b", true), named("c", true)];
    let out = super::bare_slug_candidates(&sources, Some("c"));
    let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["c", "a", "b"],
        "origin leads, listed order follows"
    );
}

#[test]
fn bare_slug_candidates_skips_disabled_and_unknown_origins() {
    let sources = [named("a", true), named("b", false), named("c", true)];
    let out = super::bare_slug_candidates(&sources, Some("b"));
    assert!(
        out.iter().all(|s| s.name != "b"),
        "disabled origin must not be probed"
    );

    let out = super::bare_slug_candidates(&sources, Some("gone"));
    let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["a", "c"], "unconfigured origin falls through");
}

// ── V-10 confirmation gate: decision matrix + non-TTY refusal ───────────────

fn gate_manifest() -> vynkor_wire::manifest::InstallManifest {
    serde_json::from_str(
        r#"{
        "plugin_id": "guarded",
        "version": "1.0.0",
        "permissions": ["storage"],
        "binary": "b",
        "kernel_compatibility_range": {"min": "0.1.0", "max": "*"}
    }"#,
    )
    .unwrap()
}

#[test]
fn confirm_mode_pins_every_branch() {
    use super::{confirm_mode, ConfirmMode};
    // scripts get --yes
    assert_eq!(confirm_mode(true, true), ConfirmMode::AutoYes);
    assert_eq!(confirm_mode(true, false), ConfirmMode::AutoYes);
    // TTY without --yes → interactive prompt
    assert_eq!(confirm_mode(false, true), ConfirmMode::Interactive);
    // non-TTY without --yes → refuse
    assert_eq!(
        confirm_mode(false, false),
        ConfirmMode::NonInteractiveRefusal
    );
}

#[test]
fn non_tty_without_yes_refuses_with_actionable_error() {
    let err = super::confirm_install(&gate_manifest(), false, false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(
            "refusing to grant undeclared-review permissions in a non-interactive run \
             — pass --yes to accept"
        ),
        "unexpected: {msg}"
    );
    // exit-code contract: generic failure until V-16 restructures classes
    assert_eq!(super::exit_code(&err), super::EXIT_FAILURE);
}

#[test]
fn yes_skips_gate_entirely_even_non_interactive() {
    assert!(
        super::confirm_install(&gate_manifest(), true, false).is_ok(),
        "--yes must proceed without a prompt in any run mode"
    );
}

// ── V-15 install-target disambiguation ─────────────────────────────────────

#[test]
fn registry_targets_unchanged_by_archive_mode() {
    use super::InstallKind;
    // bare slug still resolves registries
    assert_eq!(
        super::classify_install_target("database").unwrap(),
        InstallKind::Registry
    );
    // corp/slug still the registry flow
    assert_eq!(
        super::classify_install_target("corp/database@0.1.0").unwrap(),
        InstallKind::Registry
    );
}

#[test]
fn archive_indicators_route_to_archive_pipeline() {
    use super::InstallKind;
    for t in [
        "https://example.com/x.zip",
        "http://example.com/x.zip",
        "./x.zip",
        "../builds/x.zip",
        "/abs/path/x.zip",
        "x.zip",
    ] {
        assert_eq!(
            super::classify_install_target(t).unwrap(),
            InstallKind::Archive,
            "{t} must be an archive target"
        );
    }
}

#[test]
fn version_pin_on_archive_is_a_hard_error() {
    let err = super::classify_install_target("./x.zip@1.0").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("archives are not versioned") && msg.contains("./x.zip@1.0"),
        "unexpected: {msg}"
    );
}

// ── V-16: rendering, info picking, cache-first completion ───────────────────

fn entry(slug: &str, version: &str, status: &str) -> crate::registry::RegistryEntry {
    crate::registry::RegistryEntry {
        id: slug.into(),
        slug: slug.into(),
        name: format!("the {slug} plugin"),
        description: String::new(),
        version: version.into(),
        permissions: vec!["storage".into()],
        archive_url: format!("/{slug}.zip"),
        source_url: String::new(),
        sha256: "deadbeef".into(),
        min_kernel_version: "0.1.0".into(),
        max_kernel_version: "*".into(),
        signature: String::new(),
        status: status.into(),
    }
}

#[test]
fn render_search_json_shape_is_stable() {
    let hits = vec![
        entry("db", "2.0.0", "stable"),
        entry("x", "1.0.0", "revoked"),
    ];
    let parsed: serde_json::Value =
        serde_json::from_str(&super::render_search_json(Some("corp"), &hits)).unwrap();
    assert_eq!(parsed["resolved_from"], "corp");
    assert_eq!(parsed["results"][0]["slug"], "db");
    assert_eq!(parsed["results"][0]["status"], "stable");
    // revocation is surfaced as status, never hidden
    assert_eq!(parsed["results"][1]["status"], "revoked");

    let no_match: serde_json::Value =
        serde_json::from_str(&super::render_search_json(None, &[])).unwrap();
    assert_eq!(no_match["resolved_from"], serde_json::Value::Null);
    assert_eq!(no_match["results"].as_array().unwrap().len(), 0);
}

#[test]
fn render_search_table_has_source_column() {
    let hits = vec![entry("db", "2.0.0", "stable")];
    let table = super::render_search_table("corp", &hits);
    assert!(table.contains("SOURCE"), "V-16 adds the SOURCE column");
    assert!(table.contains(" corp "), "rows carry the serving source");
}

#[test]
fn pick_info_entry_prefers_latest_non_revoked_semver() {
    let doc = vec![
        entry("db", "1.0.0", "stable"),
        entry("db", "3.0.0", "stable"),
        entry("db", "2.0.0", "stable"),
    ];
    let picked = super::pick_info_entry(&doc, "db").unwrap();
    assert_eq!(picked.version, "3.0.0");

    let revoked_leads = vec![
        entry("db", "9.9.9", "revoked"),
        entry("db", "1.0.0", "stable"),
    ];
    let picked = super::pick_info_entry(&revoked_leads, "db").unwrap();
    assert_eq!(picked.version, "1.0.0", "revoked never wins info");

    let unparsable_only = vec![entry("db", "not-semver", "stable")];
    let picked = super::pick_info_entry(&unparsable_only, "db").unwrap();
    assert_eq!(picked.version, "not-semver", "document-order fallback");
}

#[test]
fn dry_run_preview_states_plan_without_manifest_actions() {
    let preview = super::format_entry_preview(&entry("db", "2.0.0", "beta"));
    assert!(
        preview.contains("would install db @ 2.0.0 (beta)"),
        "{preview}"
    );
    assert!(preview.contains("permissions: storage"), "{preview}");
    assert!(preview.contains("sha256: deadbeef"), "{preview}");
}

#[test]
fn cached_slugs_reads_cache_ignoring_ttl() {
    use crate::registry::{cached_slugs, RegistryCache, REGISTRY_CACHE_SCHEMA_VERSION};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("official.json");
    let cache = RegistryCache {
        schema_version: REGISTRY_CACHE_SCHEMA_VERSION,
        entries: vec![
            entry("zeta", "1.0.0", "stable"),
            entry("alpha", "1.0.0", "stable"),
            entry("zeta", "2.0.0", "stable"),
        ],
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_string(&cache).unwrap()).unwrap();
    assert_eq!(
        cached_slugs(&path),
        vec!["alpha".to_string(), "zeta".to_string()],
        "unique + sorted"
    );

    assert!(cached_slugs(&dir.path().join("absent.json")).is_empty());
    std::fs::write(dir.path().join("bad.json"), "not json{").unwrap();
    assert!(
        cached_slugs(&dir.path().join("bad.json")).is_empty(),
        "corrupt cache reads empty"
    );
}

use clap::CommandFactory as _;

#[test]
fn completions_generate_for_all_contract_shells() {
    // bash/zsh/fish are the scripting contract in VYNM_ROADMAP V-16
    for shell in [
        clap_complete::Shell::Bash,
        clap_complete::Shell::Zsh,
        clap_complete::Shell::Fish,
    ] {
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        clap_complete::generate(shell, &mut cmd, "vynm", &mut buf);
        let script = String::from_utf8(buf).unwrap();
        assert!(!script.is_empty(), "{shell:?} must emit a script");
        assert!(
            script.contains("vynm"),
            "{shell:?} script must name the binary"
        );
    }
}
