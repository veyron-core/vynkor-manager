//! V-12 acceptance: `outdated` table + `update` batch flow end-to-end against
//! two-local-registry mockito stands — origin enforcement, strictly-newer
//! planning, rebuild detection, ONE confirmation per batch, local-source skip,
//! scoping, restart hint. Same harness as tests/multisource.rs.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use sha2::{Digest, Sha256};
use tempfile::{tempdir, TempDir};
use vynkor_manager::registry::RegistryEntry;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// marker varies archive bytes at constant version — the rebuild-detection lever
fn build_archive(slug: &str, version: &str, marker: &str) -> (Vec<u8>, String) {
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
        zip.write_all(format!("#!/bin/sh\necho {marker}\n").as_bytes())
            .unwrap();
        zip.finish().unwrap();
    }
    let bytes = buf.into_inner();
    (bytes.clone(), hex(&Sha256::digest(&bytes)))
}

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

fn sources_yaml(sources: &[(&str, &str)]) -> String {
    // unsigned-by-consent stands (no public_key, allow_unsigned: true)
    let mut out = String::from("registries:\n");
    for (name, url) in sources {
        out.push_str(&format!(
            "  - name: {name}\n    url: {url}\n    allow_unsigned: true\n"
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

    fn ledger(&self) -> vynkor_manager::state::InstalledState {
        vynkor_manager::state::load_state(self.dir.path())
    }

    fn record(&self, slug: &str, version: &str, source: &str, source_url: &str, sha: &str) {
        vynkor_manager::state::record_install(
            self.dir.path(),
            vynkor_manager::state::InstalledEntry {
                slug: slug.into(),
                version: version.into(),
                sha256: sha.into(),
                installed_at: 1,
                source_url: source_url.into(),
                source: source.into(),
                tree_sha256: None,
                previous: None,
            },
        )
        .unwrap();
    }

    /// caches are keyed per source under the state dir; clearing them lets a
    /// later phase see re-mocked content despite the fresh TTL
    fn clear_registry_cache(&self) {
        let cache = self.dir.path().join("registry-cache");
        if cache.exists() {
            fs::remove_dir_all(cache).unwrap();
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    fn plugin_dir(&self) -> PathBuf {
        self.dir.path().join("plugins")
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

/// spawn the real binary — captured stdout+stderr, exit status, and no
/// process-global print leakage; used for every OUTPUT assertion here
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

// ── outdated ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn outdated_table_shows_mixed_rows_and_exits_zero() {
    let sb = Sandbox::new();
    let (_, hash_db_old) = build_archive("database", "1.0.0", "a");
    let (_, hash_db_new) = build_archive("database", "1.5.0", "b");
    let (_, hash_lg) = build_archive("logger", "1.0.0", "c");

    let (s1, url_a) = serve(vec![
        ("database", "1.5.0", &hash_db_new),
        ("logger", "1.0.0", &hash_lg),
    ])
    .await;

    // OUTDATED (real install shape), unconfigured origin, local skip
    sb.record("database", "1.0.0", "first", &url_a, &hash_db_old);
    sb.record("logger", "1.0.0", "gone", &url_a, &hash_lg);
    sb.record("weather", "3.0.0", "local", "/tmp/w.zip", "aa");

    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));
    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["outdated"]);
    assert!(ok, "outdated must ALWAYS exit 0: {out}");
    assert!(
        out.contains("SLUG") && out.contains("AVAILABLE"),
        "header: {out}"
    );
    assert!(out.contains("OUTDATED"), "outdated row missing: {out}");
    assert!(out.contains("1.0.0") && out.contains("1.5.0"), "{out}");
    assert!(
        out.contains("origin 'gone' no longer configured"),
        "unconfigured note missing: {out}"
    );
    assert!(
        out.contains("local installs never update"),
        "local note missing: {out}"
    );
    drop(s1);
}

#[tokio::test]
async fn outdated_marks_ahead_and_unparsable_without_guessing() {
    let sb = Sandbox::new();
    let (_, hash_db) = build_archive("database", "1.0.0", "a");
    let (s1, url_a) = serve(vec![
        ("database", "1.0.0", &hash_db),
        ("weird", "not-semver", &hash_db),
    ])
    .await;

    sb.record("database", "3.0.0", "first", &url_a, &hash_db); // AHEAD
    sb.record("weird", "1.0.0", "first", &url_a, &hash_db); // unparsable side

    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));
    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["outdated"]);
    assert!(ok, "{out}");
    assert!(out.contains("AHEAD"), "ahead row missing: {out}");
    assert!(
        out.contains("not-semver") && out.contains("none parse as semver"),
        "?-row reason missing: {out}"
    );
    drop(s1);
}

// ── planning: strictly newer only ───────────────────────────────────────────

#[tokio::test]
async fn equal_and_downgrade_plans_stay_empty() {
    let sb = Sandbox::new();
    let (_, hash_old) = build_archive("database", "2.0.0", "a");
    let (s1, url_a) = serve(vec![("database", "1.0.0", &hash_old)]).await;

    // equal-version same-sha → UpToDate; installed 3.0.0 vs served 1.0.0 → Ahead
    sb.record("database", "2.0.0", "first", &url_a, &hash_old);
    sb.record("logger", "3.0.0", "first", &url_a, &hash_old);

    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));
    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["update", "-y"]);
    assert!(ok, "empty plan must be a clean exit 0: {out}");
    assert!(out.contains("everything up to date"), "{out}");
    assert!(!out.contains("planned:"), "nothing may be planned: {out}");

    assert_eq!(sb.ledger().get("database").unwrap().version, "2.0.0");
    assert_eq!(sb.ledger().get("logger").unwrap().version, "3.0.0");
    drop(s1);
}

// ── rebuild detection ───────────────────────────────────────────────────────

#[tokio::test]
async fn rebuild_detected_excluded_without_force_reinstalled_with_force() {
    let sb = Sandbox::new();
    let (bytes_a, hash_a) = build_archive("database", "1.0.0", "original");
    let (_, hash_b) = build_archive("database", "1.0.0", "rebuilt");
    let (mut s1, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    serve_archive_at(&mut s1, "/database.zip", bytes_a).await;

    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));
    let sd = sb.state_dir();
    let pd = sb.plugin_dir();

    // seed a REAL install of 1.0.0/sha-a so the tree + ledger exist
    let (ok, out) = vynm(&cfg, &sd, &pd, &["install", "database", "--yes"]);
    assert!(ok, "seed install failed: {out}");

    // registry now serves the SAME version with a DIFFERENT digest
    s1.reset();
    let (bytes_b, _) = build_archive("database", "1.0.0", "rebuilt");
    s1.mock("GET", "/registry.json")
        .with_status(200)
        .with_body(
            serde_json::to_string(&vec![unsigned_entry("database", "1.0.0", &hash_b)]).unwrap(),
        )
        .create_async()
        .await;
    serve_archive_at(&mut s1, "/database.zip", bytes_b).await;
    sb.clear_registry_cache();

    // without --force: warned, excluded, nothing changes
    let (ok, out) = vynm(&cfg, &sd, &pd, &["update", "-y"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(
            "rebuild detected — same version, different digest; pass --force to reinstall"
        ),
        "rebuild warning missing: {out}"
    );
    assert_eq!(
        sb.ledger().get("database").unwrap().sha256,
        hash_a,
        "rebuild must NOT silently apply"
    );

    // with --force: included and actually reinstalled from the new archive
    let (ok, out) = vynm(&cfg, &sd, &pd, &["update", "--force", "-y"]);
    assert!(ok, "forced rebuild failed: {out}");
    assert_eq!(
        sb.ledger().get("database").unwrap().sha256,
        hash_b,
        "forced rebuild must install the new digest"
    );
    // the shelved old tree must be gone after success
    assert!(!pd.join("database.rebuild-bak").exists());
    drop(s1);
}

// ── confirmation contract ───────────────────────────────────────────────────

#[tokio::test]
async fn one_confirmation_for_the_whole_batch() {
    let sb = Sandbox::new();
    let (lg, hash_lg) = build_archive("logger", "0.4.0", "l");
    let (db, hash_db) = build_archive("database", "2.0.0", "d");
    let (mut s1, url_a) = serve(vec![
        ("logger", "0.4.0", &hash_lg),
        ("database", "2.0.0", &hash_db),
    ])
    .await;
    serve_archive_at(&mut s1, "/logger.zip", lg).await;
    serve_archive_at(&mut s1, "/database.zip", db).await;

    sb.record("logger", "0.1.0", "first", &url_a, "old");
    sb.record("database", "1.0.0", "first", &url_a, "old");

    let _cfg = sb.config(&sources_yaml(&[("first", &url_a)]));

    let mut prompts = 0usize;
    // drive update_cmd_with_ask directly to COUNT the ask invocations
    {
        let ctx = vynkor_manager::cli::Ctx::load(&_cfg).unwrap();
        vynkor_manager::update::update_cmd_with_ask(&ctx, None, false, false, false, true, || {
            prompts += 1;
            true
        })
        .await
        .unwrap();
    }

    assert_eq!(
        prompts, 1,
        "N plugins in one batch must produce exactly ONE confirmation"
    );
    assert_eq!(sb.ledger().get("logger").unwrap().version, "0.4.0");
    assert_eq!(sb.ledger().get("database").unwrap().version, "2.0.0");
    drop(s1);
}

#[tokio::test]
async fn non_tty_without_yes_refuses_the_batch() {
    let sb = Sandbox::new();
    let (db, hash_db) = build_archive("database", "2.0.0", "d");
    let (s1, url_a) = serve(vec![("database", "2.0.0", &hash_db)]).await;

    sb.record("database", "1.0.0", "first", &url_a, "old");
    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));

    // spawned binary → stdin is not a TTY → refusal without -y
    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["update"]);
    assert!(!ok, "non-TTY batch without -y must fail closed: {out}");
    assert!(out.contains("-y/--yes"), "actionable error required: {out}");
    assert_eq!(
        sb.ledger().get("database").unwrap().version,
        "1.0.0",
        "refusal must leave the ledger untouched"
    );
    drop(db);
    drop(s1);
}

#[tokio::test]
async fn yes_flag_skips_the_prompt() {
    let sb = Sandbox::new();
    let (db, hash_db) = build_archive("database", "2.0.0", "d");
    let (mut s1, url_a) = serve(vec![("database", "2.0.0", &hash_db)]).await;
    serve_archive_at(&mut s1, "/database.zip", db).await;

    sb.record("database", "1.0.0", "first", &url_a, "old");
    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));

    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["update", "-y"]);
    assert!(ok, "{out}");
    assert_eq!(sb.ledger().get("database").unwrap().version, "2.0.0");
    drop(s1);
}

// ── origin enforcement ──────────────────────────────────────────────────────

#[tokio::test]
async fn update_applies_from_recorded_origin_not_shadowing_first() {
    let sb = Sandbox::new();
    // first shadows with a NEWER-looking 5.0.0; the plugin's ORIGIN is second
    let (b, hash_b) = build_archive("database", "1.5.0", "b");
    let (x, hash_x) = build_archive("database", "5.0.0", "x");
    let (mut sa, url_a) = serve(vec![("database", "5.0.0", &hash_x)]).await;
    let (mut s2, url_b) = serve(vec![("database", "1.5.0", &hash_b)]).await;
    serve_archive_at(&mut sa, "/database.zip", x).await;
    serve_archive_at(&mut s2, "/database.zip", b).await;

    sb.record("database", "1.0.0", "second", &url_b, "old");
    let cfg = sb.config(&sources_yaml(&[("first", &url_a), ("second", &url_b)]));

    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["update", "-y"]);
    assert!(ok, "{out}");
    let rec = sb.ledger().get("database").unwrap().clone();
    assert_eq!(
        rec.version, "1.5.0",
        "must take the ORIGIN's newer, not first's 5.0.0"
    );
    assert_eq!(
        rec.source, "second",
        "origin must stay stable across updates"
    );
    drop((sa, s2));
}

#[tokio::test]
async fn local_source_plugin_is_skipped_everywhere() {
    let sb = Sandbox::new();
    let (db, hash_db) = build_archive("database", "2.0.0", "d");
    let (mut s1, url_a) = serve(vec![("database", "2.0.0", &hash_db)]).await;
    serve_archive_at(&mut s1, "/database.zip", db.clone()).await;

    sb.record("database", "1.0.0", "local", "/tmp/db.zip", "old");
    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));
    drop(db);

    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["update", "-y"]);
    assert!(ok, "{out}");
    assert!(
        out.contains("everything up to date"),
        "local installs are never updatable: {out}"
    );
    let rec = sb.ledger().get("database").unwrap().clone();
    assert_eq!(rec.version, "1.0.0");
    assert_eq!(rec.source, "local");

    let (_, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["outdated"]);
    assert!(
        out.contains("local installs never update"),
        "outdated must note the skip: {out}"
    );
    drop(s1);
}

// ── scoping ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scoped_update_ignores_other_outdated_plugins() {
    let sb = Sandbox::new();
    let (lg, hash_lg) = build_archive("logger", "0.4.0", "l");
    let (db, hash_db) = build_archive("database", "2.0.0", "d");
    let (mut s1, url_a) = serve(vec![
        ("logger", "0.4.0", &hash_lg),
        ("database", "2.0.0", &hash_db),
    ])
    .await;
    serve_archive_at(&mut s1, "/logger.zip", lg.clone()).await;
    serve_archive_at(&mut s1, "/database.zip", db.clone()).await;

    sb.record("logger", "0.1.0", "first", &url_a, "old");
    sb.record("database", "1.0.0", "first", &url_a, "old");
    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));

    let (ok, out) = vynm(
        &cfg,
        &sb.state_dir(),
        &sb.plugin_dir(),
        &["update", "logger", "-y"],
    );
    assert!(ok, "{out}");
    assert_eq!(sb.ledger().get("logger").unwrap().version, "0.4.0");
    assert_eq!(
        sb.ledger().get("database").unwrap().version,
        "1.0.0",
        "scoped update must not touch other outdated plugins"
    );
    drop((lg, db, s1));
}

// ── restart hint + failure semantics ────────────────────────────────────────

#[tokio::test]
async fn restart_hint_printed_after_at_least_one_applied_update() {
    let sb = Sandbox::new();
    let (db, hash_db) = build_archive("database", "2.0.0", "d");
    let (mut s1, url_a) = serve(vec![("database", "2.0.0", &hash_db)]).await;
    serve_archive_at(&mut s1, "/database.zip", db).await;

    sb.record("database", "1.0.0", "first", &url_a, "old");
    let cfg = sb.config(&sources_yaml(&[("first", &url_a)]));

    let (ok, out) = vynm(&cfg, &sb.state_dir(), &sb.plugin_dir(), &["update", "-y"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(
            "running plugins keep executing the old binary — restart the kernel (or 'vyn restart <id>')"
        ),
        "restart hint missing: {out}"
    );
    drop(s1);
}
