use std::fs;
use std::io::{Cursor, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use tempfile::{tempdir, TempDir};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use super::{export, import, BUNDLE_INNER_LEDGER};
use crate::dropin::plugin_dir;
use crate::error::VynmError;
use crate::installer::tree_digest;
use crate::state::{load_state, record_install, InstalledEntry, LEDGER_SCHEMA_VERSION};

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

    fn plugins_d(&self) -> std::path::PathBuf {
        self.dir.path().join("plugins.d")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        std::env::remove_var("VYNM_STATE_DIR");
        std::env::remove_var("VYNM_PLUGIN_DIR");
    }
}

/// Run `f` with a fresh sandbox and return its output — the sandbox (and the
/// env lock it holds) is GONE before `f` returns, so a test can chain a
/// source sandbox into a destination sandbox without self-deadlocking on the
/// non-reentrant ENV_LOCK.
fn with_sandbox<T>(f: impl FnOnce(&Sandbox) -> T) -> T {
    f(&Sandbox::new())
}

/// Hand-build an installed tree + ledger record without running the installer:
/// plugin.json (valid for validate_manifest; binary = payload.txt) + payload.
fn make_installed(sandbox: &Sandbox, slug: &str, version: &str, payload: &str) {
    let tree = plugin_dir(sandbox.tmp()).join(slug);
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("payload.txt"), payload).unwrap();
    let manifest = format!(
        r#"{{"plugin_id":"{slug}","version":"{version}","permissions":[],"binary":"payload.txt","kernel_compatibility_range":{{"min":"0.1.0","max":"*"}}}}"#
    );
    fs::write(tree.join("plugin.json"), manifest).unwrap();

    let entry = InstalledEntry {
        slug: slug.into(),
        version: version.into(),
        sha256: "0".repeat(64),
        installed_at: 0,
        source_url: "https://registry.example".into(),
        source: "official".into(),
        tree_sha256: Some(tree_digest(&tree).unwrap()),
        previous: None,
    };
    record_install(sandbox.tmp(), entry).unwrap();
}

/// The bundle file must live OUTSIDE both sandboxes: it is produced by the
/// source sandbox and consumed after that sandbox is gone.
fn export_bundle(
    store: &Path,
    install: impl FnOnce(&Sandbox),
    slugs: &[String],
) -> std::path::PathBuf {
    let out = store.join("bundle.zip");
    with_sandbox(|src| {
        install(src);
        export(src.tmp(), Some(&out), false, slugs).unwrap();
    });
    assert!(out.is_file());
    out
}

// ── roundtrip onto a fresh machine: trees + ledger + drop-ins ────────────────

#[test]
fn export_import_roundtrip_restores_trees_ledger_and_dropins() {
    let store = tempdir().unwrap();
    let bundle = export_bundle(
        store.path(),
        |src| {
            make_installed(src, "alpha", "1.0.0", "alpha-payload");
            make_installed(src, "beta", "2.5.1", "beta-payload");
        },
        &[],
    );

    // a fresh machine: empty state + plugin dirs
    with_sandbox(|dst| {
        let report = import(dst.tmp(), &dst.plugins_d(), &bundle, false).unwrap();
        assert_eq!(report.imported, vec!["alpha", "beta"]);
        assert!(report.skipped.is_empty());

        for (slug, payload, version) in [
            ("alpha", "alpha-payload", "1.0.0"),
            ("beta", "beta-payload", "2.5.1"),
        ] {
            let tree = plugin_dir(dst.tmp()).join(slug);
            assert_eq!(
                fs::read_to_string(tree.join("payload.txt")).unwrap(),
                payload
            );
            assert_eq!(load_state(dst.tmp()).get(slug).unwrap().version, version);
            let dropin = dst.plugins_d().join(format!("{slug}.yaml"));
            let text = fs::read_to_string(dropin).unwrap();
            assert!(text.contains(&format!("id: {slug}")), "{text}");
            assert!(text.contains("binary: "), "{text}");
        }

        // origin enforcement data traveled intact; digest re-recorded fresh
        let entry = load_state(dst.tmp()).get("alpha").unwrap().clone();
        assert_eq!(entry.source, "official");
        assert_eq!(entry.source_url, "https://registry.example");
        assert_eq!(
            entry.tree_sha256.unwrap(),
            tree_digest(&plugin_dir(dst.tmp()).join("alpha")).unwrap()
        );
    });
}

#[test]
fn filtered_export_carries_only_requested_slugs() {
    let store = tempdir().unwrap();
    let out = export_bundle(
        store.path(),
        |src| {
            make_installed(src, "alpha", "1.0.0", "a");
            make_installed(src, "beta", "1.0.0", "b");
        },
        &["alpha".to_string()],
    );

    with_sandbox(|dst| {
        let report = import(dst.tmp(), &dst.plugins_d(), &out, false).unwrap();
        assert_eq!(report.imported, vec!["alpha"]);
        assert!(load_state(dst.tmp()).get("beta").is_none());
    });
}

#[test]
fn unknown_slug_in_export_is_plugin_not_found() {
    let src = Sandbox::new();
    make_installed(&src, "alpha", "1.0.0", "a");
    let err = export(src.tmp(), None, false, &["ghost".to_string()]).unwrap_err();
    assert!(matches!(err, VynmError::PluginNotFound(_)), "{err:?}");
}

// ── exec-bit survival: mode is part of the V-13 digest ──────────────────────

#[test]
fn executable_bit_survives_export_import_roundtrip() {
    let store = tempdir().unwrap();
    let bundle = store.path().join("b.zip");

    with_sandbox(|src| {
        make_installed(src, "execme", "1.0.0", "#!/bin/sh\necho hi\n");
        // make_installed's payload is 0644 — upgrade it to a real executable
        let tree = plugin_dir(src.tmp()).join("execme");
        fs::set_permissions(tree.join("payload.txt"), fs::Permissions::from_mode(0o755)).unwrap();
        // re-stamp the digest AFTER the chmod so the ledger matches disk
        let entry = load_state(src.tmp()).get("execme").unwrap().clone();
        let mut fixed = entry.clone();
        fixed.tree_sha256 = Some(tree_digest(&tree).unwrap());
        crate::state::record_install(src.tmp(), fixed).unwrap();
        export(src.tmp(), Some(&bundle), false, &[]).unwrap();
    });

    with_sandbox(|dst| {
        import(dst.tmp(), &dst.plugins_d(), &bundle, false).unwrap();
        let restored = plugin_dir(dst.tmp()).join("execme/payload.txt");
        let mode = fs::metadata(&restored).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "exec bit must survive the bundle roundtrip");
    });
}

// ── tamper: digest mismatch aborts with NOTHING committed ────────────────────

#[test]
fn tampered_bundle_commits_nothing_and_cleans_staging() {
    use super::BUNDLE_PLUGINS_PREFIX;
    let store = tempdir().unwrap();
    let bundle = export_bundle(
        store.path(),
        |src| {
            make_installed(src, "alpha", "1.0.0", "original");
            make_installed(src, "keepme", "1.0.0", "untouched");
        },
        &[],
    );

    // rewrite one member's bytes inside the bundle
    let raw = fs::read(&bundle).unwrap();
    let mut src_zip = ZipArchive::new(Cursor::new(raw)).unwrap();
    let mut out_buf = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut out_buf);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for i in 0..src_zip.len() {
            let mut file = src_zip.by_index(i).unwrap();
            let name = file.name().to_string();
            writer.start_file(name.as_str(), opts).unwrap();
            if name == format!("{BUNDLE_PLUGINS_PREFIX}alpha/payload.txt") {
                writer.write_all(b"TAMPERED").unwrap();
            } else {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                writer.write_all(&buf).unwrap();
            }
        }
        writer.finish().unwrap();
    }
    fs::write(&bundle, out_buf.into_inner()).unwrap();

    with_sandbox(|dst| {
        make_installed(dst, "keepme", "9.9.9", "must-survive");
        let err = import(dst.tmp(), &dst.plugins_d(), &bundle, false).unwrap_err();
        assert!(
            matches!(&err, VynmError::Verification(msg) if msg.contains("alpha")),
            "{err:?}"
        );

        // nothing landed: alpha absent, pre-existing keepme untouched
        assert!(!plugin_dir(dst.tmp()).join("alpha").exists());
        assert_eq!(
            fs::read_to_string(plugin_dir(dst.tmp()).join("keepme/payload.txt")).unwrap(),
            "must-survive"
        );
        assert!(load_state(dst.tmp()).get("alpha").is_none());
        assert!(!dst.plugins_d().join("alpha.yaml").exists());

        // staging litter is gone
        let leftovers: Vec<_> = fs::read_dir(plugin_dir(dst.tmp()))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".bundle-stage"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    });
}

// ── skip / replace semantics on slug collision ────────────────────────────────

#[test]
fn existing_slug_skipped_without_force_replaced_with_force() {
    let store = tempdir().unwrap();
    let bundle = export_bundle(
        store.path(),
        |src| {
            make_installed(src, "alpha", "2.0.0", "NEW");
        },
        &[],
    );

    with_sandbox(|dst| {
        make_installed(dst, "alpha", "1.0.0", "OLD");

        let report = import(dst.tmp(), &dst.plugins_d(), &bundle, false).unwrap();
        assert_eq!(report.skipped, vec!["alpha"]);
        assert_eq!(
            fs::read_to_string(plugin_dir(dst.tmp()).join("alpha/payload.txt")).unwrap(),
            "OLD"
        );
        assert_eq!(load_state(dst.tmp()).get("alpha").unwrap().version, "1.0.0");

        let report = import(dst.tmp(), &dst.plugins_d(), &bundle, true).unwrap();
        assert_eq!(report.imported, vec!["alpha"]);
        assert_eq!(
            fs::read_to_string(plugin_dir(dst.tmp()).join("alpha/payload.txt")).unwrap(),
            "NEW"
        );
        assert_eq!(load_state(dst.tmp()).get("alpha").unwrap().version, "2.0.0");
        // drop-in left untouched when it already exists
        assert!(dst.plugins_d().join("alpha.yaml").exists());
    });
}

// ── malformed bundles ────────────────────────────────────────────────────────

fn write_raw_zip(members: &[(&str, Vec<u8>)]) -> std::path::PathBuf {
    let dir = tempdir().unwrap();
    let path = dir.path().join("raw.zip");
    let _keep = dir.keep();
    let file = fs::File::create(&path).unwrap();
    let mut writer = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in members {
        writer.start_file(*name, opts).unwrap();
        writer.write_all(body).unwrap();
    }
    writer.finish().unwrap();
    path
}

#[test]
fn malformed_inner_ledger_is_invalid_input() {
    let src = Sandbox::new();
    let bad = write_raw_zip(&[(BUNDLE_INNER_LEDGER, b"{not json".to_vec())]);
    let err = import(src.tmp(), &src.plugins_d(), &bad, false).unwrap_err();
    assert!(err.to_string().contains("malformed bundle ledger"), "{err}");
}

#[test]
fn missing_ledger_member_is_invalid_input() {
    let src = Sandbox::new();
    let bad = write_raw_zip(&[("random.txt", b"x".to_vec())]);
    let err = import(src.tmp(), &src.plugins_d(), &bad, false).unwrap_err();
    assert!(err.to_string().contains(BUNDLE_INNER_LEDGER), "{err}");
}

#[test]
fn empty_bundle_is_invalid_input() {
    let src = Sandbox::new();
    let ledger = format!(r#"{{"schema_version":{LEDGER_SCHEMA_VERSION},"entries":[]}}"#);
    let bad = write_raw_zip(&[(BUNDLE_INNER_LEDGER, ledger.into_bytes())]);
    let err = import(src.tmp(), &src.plugins_d(), &bad, false).unwrap_err();
    assert!(err.to_string().contains("no plugins"), "{err}");
}

#[test]
fn missing_tree_member_fails_verification_without_committing() {
    let src = Sandbox::new();
    let ledger = r#"{"schema_version":3,"entries":[{"slug":"ghost","version":"1.0.0","sha256":"00","installed_at":0,"source_url":"u","source":"official","tree_sha256":"ab"}]}"#;
    let bad = write_raw_zip(&[(BUNDLE_INNER_LEDGER, ledger.as_bytes().to_vec())]);
    let err = import(src.tmp(), &src.plugins_d(), &bad, false).unwrap_err();
    assert!(
        matches!(&err, VynmError::Verification(m) if m.contains("plugin.json")),
        "{err:?}"
    );
    assert!(!plugin_dir(src.tmp()).join("ghost").exists());
}
