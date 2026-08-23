//! V-13 acceptance: `vynm verify [slug]` — offline tree-digest verification
//! against the ledger. Exit contract: all OK → 0, any TAMPERED → 3, only
//! MISSING/UNKNOWN BASELINE → 1. Pattern mirrors tests/multisource.rs.
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
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

/// one-source stand serving `logger@1.0.0`; returns config path + servers
struct LoggerStand {
    _server: mockito::ServerGuard,
    cfg: String,
}

async fn logger_stand(sb: &Sandbox) -> LoggerStand {
    let (a, hash_a) = build_archive("logger", "1.0.0");
    let (mut s, url) = serve(vec![("logger", "1.0.0", &hash_a)]).await;
    serve_archive_at(&mut s, "/logger.zip", a).await;
    let cfg_path = sb.config_path();
    fs::write(&cfg_path, sources_yaml(&[("only", &url)])).unwrap();
    LoggerStand {
        _server: s,
        cfg: cfg_path,
    }
}

#[tokio::test]
async fn fresh_install_verifies_ok_with_recorded_digest() {
    let sb = Sandbox::new();
    let stand = logger_stand(&sb).await;

    sb.run(&["install", "logger", "--yes"]).await.unwrap();

    // the ledger must carry a tree digest now
    let entry = vynkor_manager::state::load_state(sb.dir.path())
        .get("logger")
        .expect("installed")
        .clone();
    let recorded = entry
        .tree_sha256
        .as_deref()
        .expect("v3 install records digest");
    assert_eq!(recorded.len(), 64);

    let (ok, code, output) = vynm(
        &stand.cfg,
        sb.dir.path(),
        &sb.dir.path().join("plugins"),
        &["verify"],
    );
    assert!(ok);
    assert_eq!(code, 0);
    assert!(output.contains("OK"), "status missing: {output}");
    assert!(
        output.contains("1 ok, 0 tampered"),
        "summary missing: {output}"
    );
}

#[tokio::test]
async fn appended_byte_reports_tampered_exit_3() {
    let sb = Sandbox::new();
    let stand = logger_stand(&sb).await;
    let plugins = sb.dir.path().join("plugins");

    sb.run(&["install", "logger", "--yes"]).await.unwrap();

    let mut bin = fs::OpenOptions::new()
        .append(true)
        .open(plugins.join("logger").join("logger"))
        .unwrap();
    bin.write_all(b"echo pwned\n").unwrap();
    drop(bin);

    let expected = vynkor_manager::state::load_state(sb.dir.path())
        .get("logger")
        .unwrap()
        .tree_sha256
        .clone()
        .unwrap();

    let (ok, code, output) = vynm(&stand.cfg, sb.dir.path(), &plugins, &["verify"]);
    assert!(!ok);
    assert_eq!(code, 3, "tampering is exit 3: {output}");
    assert!(output.contains("TAMPERED"), "{output}");
    assert!(
        output.contains(&format!("expected {expected}")),
        "expected digest missing: {output}"
    );
}

#[tokio::test]
async fn chmod_alone_reports_tampered() {
    let sb = Sandbox::new();
    let stand = logger_stand(&sb).await;
    let plugins = sb.dir.path().join("plugins");

    sb.run(&["install", "logger", "--yes"]).await.unwrap();

    let json = plugins.join("logger").join("plugin.json");
    fs::set_permissions(&json, fs::Permissions::from_mode(0o600)).unwrap();

    let (_, code, output) = vynm(&stand.cfg, sb.dir.path(), &plugins, &["verify"]);
    assert_eq!(code, 3, "mode change alone must trip the digest: {output}");
    assert!(output.contains("TAMPERED"), "{output}");
}

#[tokio::test]
async fn deleted_tree_reports_missing_exit_1() {
    let sb = Sandbox::new();
    let stand = logger_stand(&sb).await;
    let plugins = sb.dir.path().join("plugins");

    sb.run(&["install", "logger", "--yes"]).await.unwrap();
    fs::remove_dir_all(plugins.join("logger")).unwrap();

    let (ok, code, output) = vynm(&stand.cfg, sb.dir.path(), &plugins, &["verify"]);
    assert!(!ok);
    assert_eq!(code, 1, "missing-only is exit 1, not tampering: {output}");
    assert!(output.contains("MISSING"), "{output}");
    assert!(
        !output.contains("tampered") || output.contains("0 tampered"),
        "{output}"
    );
}

#[tokio::test]
async fn prev3_ledger_entry_reports_unknown_baseline_exit_1() {
    let sb = Sandbox::new();
    let stand = logger_stand(&sb).await;
    let plugins = sb.dir.path().join("plugins");

    // install, then rewind the ledger to a hand-written v2 shape (no
    // tree_sha256) while keeping the installed tree on disk
    sb.run(&["install", "logger", "--yes"]).await.unwrap();
    let v2_ledger = r#"{
  "schema_version": 2,
  "entries": [
    {
      "slug": "logger",
      "version": "1.0.0",
      "sha256": "deadbeef",
      "installed_at": 1700000000,
      "source_url": "https://registry.example",
      "source": "only"
    }
  ]
}"#;
    fs::write(vynkor_manager::state::state_path(sb.dir.path()), v2_ledger).unwrap();

    let (ok, code, output) = vynm(&stand.cfg, sb.dir.path(), &plugins, &["verify"]);
    assert!(!ok);
    assert_eq!(code, 1);
    assert!(output.contains("UNKNOWN BASELINE"), "{output}");
    assert!(output.contains("reinstall"), "{output}");
}

#[tokio::test]
async fn slug_argument_scopes_verification() {
    let sb = Sandbox::new();
    // two plugins: logger stays pristine, database gets tampered after install
    let (lg, hash_lg) = build_archive("logger", "1.0.0");
    let (db, hash_db) = build_archive("database", "1.0.0");
    let (mut s, url) = serve(vec![
        ("logger", "1.0.0", &hash_lg),
        ("database", "1.0.0", &hash_db),
    ])
    .await;
    serve_archive_at(&mut s, "/logger.zip", lg).await;
    serve_archive_at(&mut s, "/database.zip", db).await;
    let cfg_path = sb.config_path();
    fs::write(&cfg_path, sources_yaml(&[("only", &url)])).unwrap();

    let plugins = sb.dir.path().join("plugins");
    sb.run(&["install", "logger", "--yes"]).await.unwrap();
    sb.run(&["install", "database", "--yes"]).await.unwrap();
    let mut bin = fs::OpenOptions::new()
        .append(true)
        .open(plugins.join("database").join("database"))
        .unwrap();
    bin.write_all(b"extra\n").unwrap();

    // scoped to the clean slug → exit 0 even though database is tampered
    let (ok, code, output) = vynm(
        &stand_cfg_str(&cfg_path),
        sb.dir.path(),
        &plugins,
        &["verify", "logger"],
    );
    assert!(ok, "clean scoped verify failed: {output}");
    assert_eq!(code, 0);
    assert!(output.contains("1 ok, 0 tampered"), "{output}");

    // scoped to the tampered slug → exit 3
    let (_, code, output) = vynm(
        &stand_cfg_str(&cfg_path),
        sb.dir.path(),
        &plugins,
        &["verify", "database"],
    );
    assert_eq!(code, 3, "{output}");

    // unknown slug errors listing what IS installed
    let err = sb.run(&["verify", "ghost"]).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unknown plugin 'ghost'")
            && msg.contains("logger")
            && msg.contains("database"),
        "unexpected: {msg}"
    );

    // full sweep still catches both rows sorted by slug
    let (ok, code, output) = vynm(
        &stand_cfg_str(&cfg_path),
        sb.dir.path(),
        &plugins,
        &["verify"],
    );
    assert!(!ok);
    assert_eq!(code, 3);
    let db_pos = output.find("database").unwrap();
    let lg_pos = output.find("logger").unwrap();
    assert!(db_pos < lg_pos, "table must sort by slug: {output}");
    assert!(output.contains("1 ok, 1 tampered"), "{output}");
    drop(s);
}

// vynm() takes &str config; small shim so the test above reads linearly
fn stand_cfg_str(cfg: &str) -> String {
    cfg.to_string()
}
