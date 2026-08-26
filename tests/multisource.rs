//! V-09 resolution-engine acceptance: shadowing, explicit-form bypass,
//! origin enforcement, per-source consent, failover — end-to-end through the
//! real binary (`CARGO_BIN_EXE_vynm`) or `run()` against mockito registries.
//!
//! All sources here are unsigned-by-consent (no public_key, allow_unsigned:
/// true) so no signing key is needed; sha256 digests still gate installs.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use clap::Parser as _;
use sha2::{Digest, Sha256};
use tempfile::{tempdir, TempDir};
use vynkor_manager::registry::RegistryEntry;
use vynkor_manager::VynmError;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn build_archive(slug: &str, version: &str) -> (Vec<u8>, String) {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("plugin.json", opts).unwrap();
        let json = format!(
            r#"{{"plugin_id":"{slug}","version":"{version}","permissions":[],"binary":"{slug}","kernel_compatibility_range":{{"min":"0.1.0","max":"*"}}}}"#
        );
        zip.write_all(json.as_bytes()).unwrap();
        zip.start_file(slug, opts).unwrap();
        zip.write_all(b"#!/bin/sh\necho hi\n").unwrap();
        zip.finish().unwrap();
    }
    let bytes = buf.into_inner();
    (bytes.clone(), hex(&Sha256::digest(&bytes)))
}

// archive_url stays root-relative ("/<slug>.zip") — resolved against each
// registry's own base at install time, so one entry body works for any
// server. (An empty string would resolve to the registry URL itself.)
fn unsigned_entry(slug: &str, version: &str, sha256: &str) -> RegistryEntry {
    RegistryEntry {
        id: slug.into(),
        slug: slug.into(),
        name: slug.into(),
        description: format!("the {slug} plugin"),
        version: version.into(),
        permissions: vec![],
        archive_url: format!("/{slug}.zip"),
        source_url: String::new(),
        sha256: sha256.into(),
        min_kernel_version: "0.1.0".into(),
        max_kernel_version: "*".into(),
        signature: String::new(),
        status: "stable".into(),
    }
}

async fn serve(body: Vec<(&str, &str, &str)>) -> (mockito::ServerGuard, String) {
    // body = (slug, version, sha256); served as a flat registry array
    let entries: Vec<RegistryEntry> = body
        .iter()
        .map(|(slug, version, sha)| unsigned_entry(slug, version, sha))
        .collect();
    let mut server = mockito::Server::new_async().await;
    server
        .mock("GET", "/registry.json")
        .with_status(200)
        .with_body(serde_json::to_string(&entries).unwrap())
        .create_async()
        .await;
    let url = format!("{}/registry.json", server.url());
    (server, url)
}

async fn serve_archive_at(server: &mut mockito::ServerGuard, path: &str, bytes: Vec<u8>) {
    server
        .mock("GET", path)
        .with_status(200)
        .with_body(bytes)
        .create_async()
        .await;
}

fn sources_yaml(sources: &[(&str, &str, bool, bool)]) -> String {
    // (name, url, allow_unsigned, enabled)
    let mut out = String::from("registries:\n");
    for (name, url, allow_unsigned, enabled) in sources {
        out.push_str(&format!(
            "  - name: {name}\n    url: {url}\n    allow_unsigned: {allow_unsigned}\n    enabled: {enabled}\n"
        ));
    }
    out
}

struct Sandbox {
    _guard: MutexGuard<'static, ()>,
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let guard = env_guard();
        let dir = tempdir().unwrap();
        std::env::set_var("VYNM_STATE_DIR", dir.path());
        std::env::set_var("VYNM_PLUGIN_DIR", dir.path().join("plugins"));
        std::env::set_var("VYNM_KERNEL_URL", "http://127.0.0.1:1");
        for var in ["VYNM_REGISTRY_URL", "VYNM_MARKETPLACE_PUBLIC_KEY"] {
            std::env::remove_var(var);
        }
        Self { _guard: guard, dir }
    }

    fn config(&self, registries: &str) -> String {
        let path = self.dir.path().join("config.yaml");
        fs::write(&path, registries).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn ledger_sha_of(&self, slug: &str) -> Option<(String, String)> {
        vynkor_manager::state::load_state(self.dir.path())
            .get(slug)
            .map(|e| (e.source.clone(), e.sha256.clone()))
    }

    /// run() in-process with this sandbox's env
    async fn run(&self, args: &[&str]) -> Result<(), VynmError> {
        let mut argv = vec!["vynm".to_string()];
        argv.push("--config".into());
        argv.push(self.config_path());
        argv.extend(args.iter().map(|a| a.to_string()));
        let cli = vynkor_manager::cli::Cli::parse_from(argv);
        vynkor_manager::cli::run(&cli).await
    }

    fn config_path(&self) -> String {
        self.dir.path().join("config.yaml").to_str().unwrap().into()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        for var in [
            "VYNM_STATE_DIR",
            "VYNM_PLUGIN_DIR",
            "VYNM_KERNEL_URL",
            "VYNM_REGISTRY_URL",
            "VYNM_MARKETPLACE_PUBLIC_KEY",
        ] {
            std::env::remove_var(var);
        }
    }
}

/// spawn the real binary with its own env — immune to process-global races,
/// and the only way to assert printed attribution
fn vynm(config: &str, state_dir: &Path, plugin_dir: &PathBuf, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vynm"))
        .env("VYNM_STATE_DIR", state_dir)
        .env("VYNM_PLUGIN_DIR", plugin_dir)
        .env("VYNM_KERNEL_URL", "http://127.0.0.1:1")
        .env_remove("VYNM_REGISTRY_URL")
        .env_remove("VYNM_MARKETPLACE_PUBLIC_KEY")
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), format!("{stdout}{stderr}"))
}

fn dead_url() -> &'static str {
    "http://127.0.0.1:1/registry.json"
}

#[tokio::test]
async fn bare_slug_shadowing_picks_first_listed_and_prints_attribution() {
    let sb = Sandbox::new();
    // distinct versions per source — the recorded version proves which won
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (b, hash_b) = build_archive("database", "2.0.0");
    let (mut sa, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (mut s2, url_b) = serve(vec![("database", "2.0.0", &hash_b)]).await;
    serve_archive_at(&mut sa, "/database.zip", a).await;
    serve_archive_at(&mut s2, "/database.zip", b).await;

    let cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    let (ok, output) = vynm(
        &cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["install", "database", "--yes"],
    );
    assert!(ok, "install failed: {output}");
    assert!(
        output.contains("resolved from first"),
        "attribution missing: {output}"
    );

    let rec = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(rec.source, "first");
    assert_eq!(rec.version, "1.0.0", "FIRST listed source must win");
}

#[tokio::test]
async fn explicit_form_bypasses_search_even_when_shadowed() {
    let sb = Sandbox::new();
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (b, hash_b) = build_archive("database", "2.0.0");
    let (mut sa, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (mut s2, url_b) = serve(vec![("database", "2.0.0", &hash_b)]).await;
    serve_archive_at(&mut sa, "/database.zip", a).await;
    serve_archive_at(&mut s2, "/database.zip", b).await;

    let _cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    sb.run(&["install", "second/database", "--yes"])
        .await
        .unwrap();

    let (source, sha) = sb.ledger_sha_of("database").expect("installed");
    assert_eq!(source, "second");
    assert_eq!(sha, hash_b, "explicit form must target the NAMED source");
}

#[tokio::test]
async fn unknown_explicit_source_errors_listing_configured_names() {
    let sb = Sandbox::new();
    let (_, hash_a) = build_archive("database", "1.0.0");
    let (s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;

    let _cfg = sb.config(&sources_yaml(&[("first", &url_a, true, true)]));

    let err = sb.run(&["install", "nope/database"]).await.unwrap_err();
    let msg = err.to_string();
    drop(s1);
    assert!(msg.contains("unknown source 'nope'"), "unexpected: {msg}");
    assert!(
        msg.contains("configured sources: first"),
        "unexpected: {msg}"
    );
}

#[tokio::test]
async fn unknown_source_flag_errors_listing_configured_names() {
    let sb = Sandbox::new();
    let (_, hash_a) = build_archive("database", "1.0.0");
    let (s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (s2, url_b) = serve(vec![("other", "1.0.0", &hash_a)]).await;

    let _cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    let err = sb
        .run(&["install", "database", "--source", "nope"])
        .await
        .unwrap_err();
    let msg = err.to_string();
    drop((s1, s2));
    assert!(
        msg.contains("configured sources: first, second"),
        "unexpected: {msg}"
    );
}

// §7.2 origin enforcement: ledger says source=second → bare install resolves
// AGAINST second first, even though first shadows the slug earlier in order
#[tokio::test]
async fn ledger_origin_resolves_against_recorded_source_first() {
    let sb = Sandbox::new();
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (b, hash_b) = build_archive("database", "2.0.0");
    let (mut sa, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (mut s2, url_b) = serve(vec![("database", "2.0.0", &hash_b)]).await;
    serve_archive_at(&mut sa, "/database.zip", a).await;
    serve_archive_at(&mut s2, "/database.zip", b).await;

    let _cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    // pre-existing install recorded from `second` (older version → full
    // pipeline runs instead of the same-version skip)
    vynkor_manager::state::record_install(
        sb.dir.path(),
        vynkor_manager::state::InstalledEntry {
            slug: "database".into(),
            version: "0.0.1".into(),
            sha256: "old".into(),
            installed_at: 1,
            source_url: url_b.clone(),
            source: "second".into(),
            tree_sha256: None,
            previous: None,
        },
    )
    .unwrap();

    sb.run(&["install", "database", "--yes"]).await.unwrap();

    let rec = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(
        rec.source, "second",
        "origin must win over listed-first shadow"
    );
    assert_eq!(rec.version, "2.0.0");
}

// a fetch error on one source skips to the next instead of aborting
#[tokio::test]
async fn probe_skips_unreachable_source() {
    let sb = Sandbox::new();
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (mut s2, url_b) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    serve_archive_at(&mut s2, "/database.zip", a).await;

    let _cfg = sb.config(&sources_yaml(&[
        ("dead", dead_url(), true, true),
        ("second", &url_b, true, true),
    ]));

    sb.run(&["install", "database", "--yes"]).await.unwrap();
    let (source, _) = sb.ledger_sha_of("database").expect("installed");
    assert_eq!(source, "second");
}

#[tokio::test]
async fn not_found_anywhere_lists_tried_sources() {
    let sb = Sandbox::new();
    let (s1, url_a) = serve(vec![]).await;
    let (s2, url_b) = serve(vec![]).await;

    let _cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    let err = sb.run(&["install", "ghost"]).await.unwrap_err();
    let msg = err.to_string();
    drop((s1, s2));
    assert!(
        msg.contains("'ghost' not found in any configured source"),
        "unexpected: {msg}"
    );
    assert!(msg.contains("tried: first, second"), "unexpected: {msg}");
}

// §7.3 knob flips only its OWN source: unconsented source hard-errors during
// the probe but the consented one still serves
#[tokio::test]
async fn allow_unsigned_is_per_source_during_probe() {
    let sb = Sandbox::new();
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (mut s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (mut s2, url_b) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    serve_archive_at(&mut s1, "/database.zip", a.clone()).await;
    serve_archive_at(&mut s2, "/database.zip", a).await;

    // listed order: corp has NO consent → its probe fails; open consents
    let _cfg = sb.config(&sources_yaml(&[
        ("corp", &url_a, false, true),
        ("open", &url_b, true, true),
    ]));

    sb.run(&["install", "database", "--yes"]).await.unwrap();
    let (source, _) = sb.ledger_sha_of("database").expect("installed");
    assert_eq!(source, "open", "consent on 'corp' must not leak to 'open'");
}

#[tokio::test]
async fn disabled_sources_are_skipped_in_generic_order() {
    let sb = Sandbox::new();
    // `off` serves a NEWER version so the pinned install re-runs the full
    // pipeline and re-records its origin (a same-version install would skip)
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (b, _hash_b) = build_archive("database", "2.0.0");
    // s1 backs `on` (v1.0.0), s2 backs `off` (v2.0.0)
    let (mut s1, url_on) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (mut s2, url_off) = serve(vec![("database", "2.0.0", &_hash_b)]).await;
    serve_archive_at(&mut s1, "/database.zip", a.clone()).await;
    serve_archive_at(&mut s2, "/database.zip", b).await;

    let _cfg = sb.config(&sources_yaml(&[
        ("off", &url_off, true, false),
        ("on", &url_on, true, true),
    ]));

    sb.run(&["install", "database", "--yes"]).await.unwrap();
    let got = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(got.source, "on");

    // ...but explicit pinning still reaches a disabled source (operator
    // asked for it by name)
    sb.run(&["install", "off/database", "--yes"]).await.unwrap();
    let got = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(got.source, "off");
    assert_eq!(got.version, "2.0.0");
}

#[tokio::test]
async fn search_resolves_first_matching_source_and_attributes_it() {
    let sb = Sandbox::new();
    let (_, hash_a) = build_archive("database", "1.0.0");
    let (s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (s2, url_b) = serve(vec![("database", "9.9.9", &hash_a)]).await;

    let cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    let (ok, output) = vynm(
        &cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["search", "data"],
    );
    assert!(ok, "search failed: {output}");
    assert!(
        output.contains("resolved from first"),
        "attribution missing: {output}"
    );
    drop((s1, s2));
}

#[tokio::test]
async fn search_with_source_flag_pins_one_registry() {
    let sb = Sandbox::new();
    let (_, hash_a) = build_archive("database", "1.0.0");
    let (s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (s2, url_b) = serve(vec![("database", "9.9.9", &hash_a)]).await;

    let cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));

    let (ok, output) = vynm(
        &cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["search", "data", "--source", "second"],
    );
    assert!(ok, "search failed: {output}");
    assert!(
        output.contains("resolved from second") && output.contains("9.9.9"),
        "wrong source pinned: {output}"
    );
    drop((s1, s2));
}

// ── list --source: filter rows by ledger origin, validate the name ─────────

#[tokio::test]
async fn list_filters_by_source_flag_and_validates_name() {
    let sb = Sandbox::new();
    // first: database@1.0.0 + logger; second: database@2.0.0
    let (db1, hash_db1) = build_archive("database", "1.0.0");
    let (lg, hash_lg) = build_archive("logger", "1.0.0");
    let (db2, hash_db2) = build_archive("database", "2.0.0");
    let (mut s1, url_a) = serve(vec![
        ("database", "1.0.0", &hash_db1),
        ("logger", "1.0.0", &hash_lg),
    ])
    .await;
    let (mut s2, url_b) = serve(vec![("database", "2.0.0", &hash_db2)]).await;
    serve_archive_at(&mut s1, "/database.zip", db1).await;
    serve_archive_at(&mut s1, "/logger.zip", lg).await;
    serve_archive_at(&mut s2, "/database.zip", db2).await;

    let cfg = sb.config(&sources_yaml(&[
        ("first", &url_a, true, true),
        ("second", &url_b, true, true),
    ]));
    let state_dir = sb.dir.path().to_path_buf();
    let plugin_dir = sb.dir.path().join("plugins");

    sb.run(&["install", "logger", "--yes"]).await.unwrap(); // bare → first
    sb.run(&["install", "second/database", "--yes"])
        .await
        .unwrap();

    let (ok, out) = vynm(&cfg, &state_dir, &plugin_dir, &["list"]);
    assert!(ok);
    assert!(out.contains("logger") && out.contains("first"));
    assert!(out.contains("database") && out.contains("second"));

    let (ok, out) = vynm(
        &cfg,
        &state_dir,
        &plugin_dir,
        &["list", "--source", "first"],
    );
    assert!(ok);
    assert!(out.contains("logger"), "row missing: {out}");
    assert!(!out.contains("database"), "filter leaked: {out}");

    let (ok, out) = vynm(
        &cfg,
        &state_dir,
        &plugin_dir,
        &["list", "--source", "second"],
    );
    assert!(ok);
    assert!(out.contains("database"), "row missing: {out}");
    assert!(!out.contains("logger"), "filter leaked: {out}");

    // unknown name → the configured-sources listing error, even mid-flight
    let err = sb.run(&["list", "--source", "nope"]).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("configured sources: first, second"),
        "unexpected: {err}"
    );
    drop((s1, s2));
}

#[tokio::test]
async fn list_from_empty_source_prints_friendly_line() {
    let sb = Sandbox::new();
    let (_, hash_a) = build_archive("database", "1.0.0");
    let (s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;

    let cfg = sb.config(&sources_yaml(&[("first", &url_a, true, true)]));

    let (ok, out) = vynm(
        &cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["list", "--source", "first"],
    );
    assert!(ok);
    assert!(
        out.contains("no plugins installed from 'first'"),
        "unexpected: {out}"
    );
    drop(s1);
}
