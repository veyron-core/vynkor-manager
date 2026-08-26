//! V-11 acceptance: `vynm install [<source>/]<slug>@<exact-version>` —
//! pinned hits resolve across/within sources, misses list per-source
//! availability, and pinned installs run the full pipeline (V-10 gate,
//! signature/digest) unchanged. Pattern mirrors tests/multisource.rs.
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

fn unsigned_entry(slug: &str, version: &str, sha256: &str) -> RegistryEntry {
    RegistryEntry {
        id: slug.into(),
        slug: slug.into(),
        name: slug.into(),
        description: format!("the {slug} plugin"),
        version: version.into(),
        permissions: vec![],
        archive_url: format!("/{slug}-{version}.zip"),
        source_url: String::new(),
        sha256: sha256.into(),
        min_kernel_version: "0.1.0".into(),
        max_kernel_version: "*".into(),
        signature: String::new(),
        status: "stable".into(),
    }
}

/// serve a flat registry doc; body = (slug, version, sha256)
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
    // all sources unsigned-by-consent, enabled
    let mut out = String::from("registries:\n");
    for (name, url) in sources {
        out.push_str(&format!(
            "  - name: {name}\n    url: {url}\n    allow_unsigned: true\n    enabled: true\n"
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

    fn config_path(&self) -> String {
        self.dir.path().join("config.yaml").to_str().unwrap().into()
    }

    fn config(&self, registries: &str) -> String {
        let path = self.dir.path().join("config.yaml");
        fs::write(&path, registries).unwrap();
        path.to_str().unwrap().to_string()
    }

    async fn run(&self, args: &[&str]) -> Result<(), VynmError> {
        let mut argv = vec!["vynm".to_string(), "--config".into(), self.config_path()];
        argv.extend(args.iter().map(|a| a.to_string()));
        let cli = vynkor_manager::cli::Cli::parse_from(argv);
        vynkor_manager::cli::run(&cli).await
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

fn vynm(
    config: &str,
    state_dir: &Path,
    plugin_dir: &PathBuf,
    args: &[&str],
) -> (bool, i32, String) {
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
    (
        out.status.success(),
        out.status.code().unwrap_or(-1),
        format!("{stdout}{stderr}"),
    )
}

// two-source stand: first serves database@1.0.0, second serves 2.0.0 —
// a bare install must pick 1.0.0 (listed order), the pin must reach 2.0.0
struct TwoSourceStand {
    _s1: mockito::ServerGuard,
    _s2: mockito::ServerGuard,
    cfg: String,
}

async fn two_source_stand(sb: &Sandbox) -> TwoSourceStand {
    let (a, hash_a) = build_archive("database", "1.0.0");
    let (b, hash_b) = build_archive("database", "2.0.0");
    let (mut sa, url_a) = serve(vec![("database", "1.0.0", &hash_a)]).await;
    let (mut s2, url_b) = serve(vec![("database", "2.0.0", &hash_b)]).await;
    serve_archive_at(&mut sa, "/database-1.0.0.zip", a).await;
    serve_archive_at(&mut s2, "/database-2.0.0.zip", b).await;
    let cfg = sb.config(&sources_yaml(&[("first", &url_a), ("second", &url_b)]));
    TwoSourceStand {
        _s1: sa,
        _s2: s2,
        cfg,
    }
}

#[tokio::test]
async fn pinned_hit_installs_exactly_that_version_across_sources() {
    let sb = Sandbox::new();
    let stand = two_source_stand(&sb).await;

    // sanity baseline: bare install takes listed-first 1.0.0
    sb.run(&["install", "database", "--yes"]).await.unwrap();
    let rec = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(rec.version, "1.0.0");

    // now pin 2.0.0 → probes first (miss), lands on second
    let (ok, code, output) = vynm(
        &stand.cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["install", "database@2.0.0", "--yes"],
    );
    assert!(ok, "pinned install failed: {output}");
    assert_eq!(code, 0);
    assert!(
        output.contains("resolved from second"),
        "attribution missing: {output}"
    );

    let rec = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(rec.version, "2.0.0", "pin must override listed order");
    assert_eq!(rec.source, "second");
}

#[tokio::test]
async fn pinned_miss_lists_versions_per_tried_source() {
    let sb = Sandbox::new();
    let stand = two_source_stand(&sb).await;

    let (ok, code, output) = vynm(
        &stand.cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["install", "database@9.9.3"],
    );
    assert!(!ok);
    assert_eq!(code, 1, "miss is exit-code 1: {output}");
    assert!(
        output.contains("first serves 1.0.0"),
        "availability missing: {output}"
    );
    assert!(
        output.contains("second serves 2.0.0"),
        "availability missing: {output}"
    );
}

#[tokio::test]
async fn source_scoped_pin_installs_from_that_source_only() {
    let sb = Sandbox::new();
    let stand = two_source_stand(&sb).await;

    let (ok, _, output) = vynm(
        &stand.cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["install", "first/database@1.0.0", "--yes"],
    );
    assert!(ok, "scoped pinned install failed: {output}");
    let rec = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(rec.source, "first");
    assert_eq!(rec.version, "1.0.0");

    // unknown version on the NAMED source errors listing only that source's
    // versions — second is never consulted for an explicit form
    let (ok, code, output) = vynm(
        &stand.cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["install", "first/database@unknown-ver"],
    );
    assert!(!ok);
    assert_eq!(code, 1);
    assert!(
        output.contains("first serves 1.0.0") && !output.contains("second serves"),
        "explicit pin must not consult other sources: {output}"
    );
}

#[tokio::test]
async fn pinned_install_runs_the_v10_gate() {
    let sb = Sandbox::new();
    let stand = two_source_stand(&sb).await;
    let state = sb.dir.path().to_path_buf();
    let plugins = sb.dir.path().join("plugins");

    // non-TTY without --yes → refusal BEFORE anything is written
    let (ok, _, output) = vynm(&stand.cfg, &state, &plugins, &["install", "database@2.0.0"]);
    assert!(!ok, "gate must refuse non-interactive installs: {output}");
    assert!(
        output.contains("pass --yes to accept"),
        "unexpected refusal text: {output}"
    );
    assert!(
        vynkor_manager::state::load_state(&state)
            .get("database")
            .is_none()
            || vynkor_manager::state::load_state(&state)
                .get("database")
                .map(|e| e.version.as_str())
                != Some("2.0.0"),
        "refused install must not record the pinned version"
    );

    // --yes passes the gate and completes the pinned install
    let (ok, _, output) = vynm(
        &stand.cfg,
        &state,
        &plugins,
        &["install", "database@2.0.0", "--yes"],
    );
    assert!(ok, "gated pinned install failed: {output}");
    let state_after = vynkor_manager::state::load_state(&state);
    let rec = state_after.get("database").expect("installed");
    assert_eq!(rec.version, "2.0.0");
}

// origin enforcement composes with pinning: ledger origin=second goes FIRST
#[tokio::test]
async fn pinned_bare_slug_tries_ledger_origin_first() {
    let sb = Sandbox::new();
    // both sources serve BOTH versions; distinct archive hashes prove which
    // entry won. Origin (second) must be probed before first.
    let (_, hash_1) = build_archive("database", "1.0.0");
    let (_, hash_2) = build_archive("database", "2.0.0");
    let (mut s1, url_a) = serve(vec![
        ("database", "1.0.0", &hash_1),
        ("database", "2.0.0", &hash_2),
    ])
    .await;
    let (mut s2, url_b) = serve(vec![
        ("database", "1.0.0", &hash_1),
        ("database", "2.0.0", &hash_2),
    ])
    .await;
    serve_archive_at(
        &mut s1,
        "/database-1.0.0.zip",
        build_archive("database", "1.0.0").0,
    )
    .await;
    serve_archive_at(
        &mut s2,
        "/database-2.0.0.zip",
        build_archive("database", "2.0.0").0,
    )
    .await;

    let _cfg = sb.config(&sources_yaml(&[("first", &url_a), ("second", &url_b)]));

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

    sb.run(&["install", "database@2.0.0", "--yes"])
        .await
        .unwrap();
    let rec = vynkor_manager::state::load_state(sb.dir.path())
        .get("database")
        .expect("installed")
        .clone();
    assert_eq!(rec.source, "second", "origin must be probed first");
    assert_eq!(rec.version, "2.0.0");
}
