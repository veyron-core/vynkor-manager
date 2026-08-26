use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use tempfile::{tempdir, TempDir};

use super::run;
use crate::dropin::plugin_dir;
use crate::error::VynmError;
use crate::installer::{install_archive, tree_digest, ArchiveOrigin};
use crate::state::load_state;

const MAX_ARCHIVE: u64 = 1024 * 1024;
const MAX_EXTRACTED: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

// redirect both state and plugin dirs into a temp sandbox (mirrors the
// integration-test Sandbox); a held mutex serializes env access across
// parallel async tests, Drop restores.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Sandbox {
    _guard: MutexGuard<'static, ()>,
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        std::env::set_var("VYNM_STATE_DIR", dir.path());
        std::env::set_var("VYNM_PLUGIN_DIR", dir.path().join("plugins"));
        Self { _guard: guard, dir }
    }

    fn tmp(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        std::env::remove_var("VYNM_STATE_DIR");
        std::env::remove_var("VYNM_PLUGIN_DIR");
    }
}

/// Build a plugin archive: `plugin.json` (minimal valid manifest) + a dummy
/// exec binary + a `VERSION` marker so the two versions' trees differ.
fn build_version_archive(slug: &str, version: &str) -> Vec<u8> {
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
        zip.write_all(format!("#!/bin/sh\necho {version}\n").as_bytes())
            .unwrap();
        zip.start_file("VERSION", opts).unwrap();
        zip.write_all(version.as_bytes()).unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

async fn install_version(sandbox: &Sandbox, slug: &str, version: &str) -> String {
    let zip_path = sandbox.tmp().join(format!("{slug}-{version}.zip"));
    fs::write(&zip_path, build_version_archive(slug, version)).unwrap();
    let installed = install_archive(
        &ArchiveOrigin::LocalPath(zip_path.clone()),
        sandbox.tmp(),
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        false,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(installed.version, version);
    zip_path.display().to_string()
}

fn version_marker(sandbox: &Sandbox, slug: &str) -> String {
    fs::read_to_string(plugin_dir(sandbox.tmp()).join(slug).join("VERSION")).unwrap()
}

// ── full cycle: install 0.1.0, install 0.2.0 over it, rollback twice ───────

#[tokio::test]
async fn rollback_toggles_between_versions() {
    let sandbox = Sandbox::new();

    install_version(&sandbox, "pong", "0.1.0").await;
    install_version(&sandbox, "pong", "0.2.0").await;

    let base = plugin_dir(sandbox.tmp());
    assert!(base.join("pong.prev").is_dir(), ".prev kept by pipeline");
    assert_eq!(version_marker(&sandbox, "pong"), "0.2.0");
    assert_eq!(
        fs::read_to_string(base.join("pong.prev").join("VERSION")).unwrap(),
        "0.1.0"
    );

    // ledger: current 0.2.0 with previous 0.1.0
    let rec = load_state(sandbox.tmp()).get("pong").unwrap().clone();
    assert_eq!(rec.version, "0.2.0");
    let prev = rec.previous.clone().expect("previous recorded");
    assert_eq!(prev.version, "0.1.0");

    run(sandbox.tmp(), "pong").unwrap();

    // trees swapped
    assert_eq!(version_marker(&sandbox, "pong"), "0.1.0");
    assert_eq!(
        fs::read_to_string(base.join("pong.prev").join("VERSION")).unwrap(),
        "0.2.0"
    );

    // ledger swapped: current 0.1.0, previous 0.2.0
    let rec = load_state(sandbox.tmp()).get("pong").unwrap().clone();
    assert_eq!(rec.version, "0.1.0");
    let prev = rec.previous.clone().expect("previous recorded");
    assert_eq!(prev.version, "0.2.0");

    // verify-style: the restored current tree re-digests to its ledger digest
    let redigest = tree_digest(&base.join("pong")).unwrap();
    assert_eq!(Some(redigest.as_str()), rec.tree_sha256.as_deref());

    // second rollback toggles back to 0.2.0
    run(sandbox.tmp(), "pong").unwrap();
    assert_eq!(version_marker(&sandbox, "pong"), "0.2.0");
    let rec = load_state(sandbox.tmp()).get("pong").unwrap().clone();
    assert_eq!(rec.version, "0.2.0");
    assert_eq!(rec.previous.as_ref().unwrap().version, "0.1.0");
}

// ── tamper: modifying .prev trips the integrity gate, nothing changes ───────

#[tokio::test]
async fn tampered_prev_refuses_and_leaves_everything_untouched() {
    let sandbox = Sandbox::new();

    install_version(&sandbox, "pong", "0.1.0").await;
    install_version(&sandbox, "pong", "0.2.0").await;

    let base = plugin_dir(sandbox.tmp());
    let before = load_state(sandbox.tmp()).get("pong").unwrap().clone();

    fs::write(base.join("pong.prev").join("VERSION"), "tampered").unwrap();

    let err = run(sandbox.tmp(), "pong").unwrap_err();
    assert!(
        matches!(&err, VynmError::Verification(m) if m.contains("integrity check")),
        "expected Verification, got: {err}"
    );

    // dest tree, .prev tree and ledger all unchanged
    assert_eq!(version_marker(&sandbox, "pong"), "0.2.0");
    assert_eq!(
        fs::read_to_string(base.join("pong.prev").join("VERSION")).unwrap(),
        "tampered"
    );
    let after = load_state(sandbox.tmp()).get("pong").unwrap().clone();
    assert_eq!(after.version, before.version);
    assert_eq!(after.tree_sha256, before.tree_sha256);
    assert_eq!(after.previous, before.previous);
}

// ── no previous: fresh single install ───────────────────────────────────────

#[tokio::test]
async fn fresh_install_has_nothing_to_roll_back_to() {
    let sandbox = Sandbox::new();
    install_version(&sandbox, "pong", "0.1.0").await;

    let err = run(sandbox.tmp(), "pong").unwrap_err();
    assert!(
        matches!(&err, VynmError::InvalidInput(m) if m.contains("no previous version")),
        "unexpected: {err}"
    );
}

// ── previous recorded but .prev dir missing ─────────────────────────────────

#[tokio::test]
async fn missing_prev_dir_is_invalid_input() {
    let sandbox = Sandbox::new();
    install_version(&sandbox, "pong", "0.1.0").await;
    install_version(&sandbox, "pong", "0.2.0").await;

    let base = plugin_dir(sandbox.tmp());
    fs::remove_dir_all(base.join("pong.prev")).unwrap();

    let err = run(sandbox.tmp(), "pong").unwrap_err();
    assert!(
        matches!(&err, VynmError::InvalidInput(m) if m.contains("missing")),
        "unexpected: {err}"
    );
}

// ── pipeline behaviour: fresh install has no .prev; overwrite keeps one ─────

#[tokio::test]
async fn pipeline_creates_prev_only_on_overwrite_and_preserves_demoted_fields() {
    let sandbox = Sandbox::new();

    let first_zip = install_version(&sandbox, "pong", "0.1.0").await;
    let base = plugin_dir(sandbox.tmp());

    // fresh install: no .prev, previous None
    assert!(!base.join("pong.prev").exists());
    assert!(load_state(sandbox.tmp())
        .get("pong")
        .unwrap()
        .previous
        .is_none());

    let first_sha = load_state(sandbox.tmp())
        .get("pong")
        .unwrap()
        .sha256
        .clone();

    install_version(&sandbox, "pong", "0.2.0").await;

    assert!(base.join("pong.prev").is_dir());
    let rec = load_state(sandbox.tmp()).get("pong").unwrap().clone();
    let prev = rec
        .previous
        .clone()
        .expect("previous recorded on overwrite");

    // demoted record's fields preserved: source "local", source_url = the
    // first zip's path, sha256 = the first archive's digest
    assert_eq!(prev.version, "0.1.0");
    assert_eq!(prev.sha256, first_sha);
    assert_eq!(prev.source, "local");
    assert_eq!(prev.source_url, first_zip);
    assert!(prev.tree_sha256.is_some());
}

// ── old-ledger compat: a JSON without `previous` loads, rollback reports ─────

#[tokio::test]
async fn ledger_without_previous_field_loads_and_reports_no_previous() {
    let sandbox = Sandbox::new();
    let state_dir = sandbox.tmp();
    fs::create_dir_all(state_dir).unwrap();
    fs::write(
        state_dir.join("installed.json"),
        r#"{
  "schema_version": 3,
  "entries": [
    {
      "slug": "pong",
      "version": "0.2.0",
      "sha256": "abc123",
      "installed_at": 1700000000,
      "source_url": "https://registry.example",
      "source": "official",
      "tree_sha256": null
    }
  ]
}"#,
    )
    .unwrap();

    let rec = load_state(state_dir).get("pong").unwrap().clone();
    assert!(rec.previous.is_none(), "missing previous defaults to None");

    let err = run(state_dir, "pong").unwrap_err();
    assert!(
        matches!(&err, VynmError::InvalidInput(m) if m.contains("no previous version")),
        "unexpected: {err}"
    );
}
