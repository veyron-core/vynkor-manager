//! Installer tests, ported from the kernel's `tests/unit/test_installer.rs`
//! security-boundary cases (V-05) plus the new D2/D3 acceptance tests.
//!
//! End-to-end installs run against mockito-served archives with entries
//! signed by a deterministic test key — never a real maintainer key.

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tempfile::{tempdir, TempDir};
use vynkor_manager::dropin::{disable_plugin_config, enable_plugin_config, plugin_dir, Toggle};
use vynkor_manager::installer::{
    extract_zip, format_local_archive_notice, format_permission_preview, install, install_archive,
    skip_reinstall, ArchiveOrigin,
};
use vynkor_manager::registry::{signed_message, RegistryEntry};
use vynkor_manager::source::RegistrySource;
use vynkor_manager::state::{load_state, record_install};
use vynkor_manager::VynmError;

const MAX_ARCHIVE: u64 = 1024 * 1024;
const MAX_EXTRACTED: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

// deterministic test keypair — never a real maintainer key
fn test_signer() -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let vk = VerifyingKey::from(&sk);
    (sk, hex_encode(vk.as_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn make_entry(slug: &str, min: &str, max: &str) -> RegistryEntry {
    RegistryEntry {
        id: "001".into(),
        slug: slug.into(),
        name: slug.into(),
        description: String::new(),
        version: "1.0.0".into(),
        permissions: vec![],
        archive_url: String::new(),
        source_url: String::new(),
        sha256: String::new(),
        min_kernel_version: min.into(),
        max_kernel_version: max.into(),
        signature: String::new(),
        status: "stable".into(),
    }
}

// sign the canonical S1 message for this entry under the given key
fn sign_entry(sk: &SigningKey, entry: &mut RegistryEntry) {
    let msg = signed_message(entry);
    let sig: Signature = sk.sign(msg.as_bytes());
    entry.signature = hex_encode(&sig.to_bytes());
}

/// Build a plugin archive in memory: `plugin.json` + an executable payload.
/// Returns (bytes, sha256-hex). `manifest_extra` splices extra manifest keys
/// before the closing brace (e.g. `, "sandbox": false`).
fn build_archive(slug: &str, manifest_extra: &str) -> (Vec<u8>, String) {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("plugin.json", opts).unwrap();
        let json = format!(
            r#"{{"plugin_id":"{slug}","version":"1.0.0","permissions":[],"binary":"{slug}","kernel_compatibility_range":{{"min":"0.1.0","max":"*"}}{manifest_extra}}}"#
        );
        zip.write_all(json.as_bytes()).unwrap();
        zip.start_file(slug, opts).unwrap();
        zip.write_all(b"#!/bin/sh\necho hi\n").unwrap();
        zip.finish().unwrap();
    }
    let bytes = buf.into_inner();
    let hash = hex_encode(&Sha256::digest(&bytes));
    (bytes, hash)
}

fn signed_archive_entry(
    sk: &SigningKey,
    slug: &str,
    archive_url: &str,
    sha256: &str,
    min: &str,
) -> RegistryEntry {
    let mut e = make_entry(slug, min, "*");
    e.archive_url = archive_url.into();
    e.sha256 = sha256.into();
    sign_entry(sk, &mut e);
    e
}

fn test_source(url: &str, pub_key: Option<String>) -> RegistrySource {
    RegistrySource {
        name: "test".into(),
        url: url.into(),
        public_key: pub_key,
        allow_unsigned: true, // mockito transport is http://127.0.0.1
        cache_ttl_secs: 3600,
        enabled: true,
    }
}

// redirect both state and plugin dirs into a temp sandbox; point the kernel
// pre-flight at a dead port so D2 takes the deterministic None path.
// Held mutex serializes env access across parallel async tests; Drop restores.
use std::sync::{Mutex, MutexGuard};

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
        std::env::set_var("VYNM_KERNEL_URL", "http://127.0.0.1:1");
        Self { _guard: guard, dir }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        std::env::remove_var("VYNM_STATE_DIR");
        std::env::remove_var("VYNM_PLUGIN_DIR");
        std::env::remove_var("VYNM_KERNEL_URL");
    }
}

#[tokio::test]
async fn install_refuses_revoked_entry() {
    let _sandbox = Sandbox::new();
    let mut entry = make_entry("revoked-plugin", "0.1.0", "*");
    entry.status = "revoked".into();
    let err = install(
        &[entry],
        "revoked-plugin",
        &test_source("https://registry.example", None),
        Path::new("/nonexistent-tmp"),
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("revoked") && msg.contains("do not install"),
        "unexpected: {msg}"
    );
}

#[tokio::test]
async fn install_end_to_end_happy_path() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive("ping-pong", "");
    let url = format!("{}/ping-pong.zip", server.url());
    let mock = server
        .mock("GET", "/ping-pong.zip")
        .with_status(200)
        .with_body(archive.clone())
        .expect(1)
        .create_async()
        .await;

    let (sk, pk_hex) = test_signer();
    let entry = signed_archive_entry(&sk, "ping-pong", &url, &hash, "0.1.0");
    let src = test_source(&format!("{}/registry.json", server.url()), Some(pk_hex));

    let installed = install(
        &[entry],
        "ping-pong",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap();

    assert_eq!(installed.slug, "ping-pong");
    assert_eq!(installed.plugin_id, "ping-pong");
    assert_eq!(installed.version, "1.0.0");
    // D3 default: no sandbox field → hint stays true
    assert!(installed.sandbox_hint);
    assert!(installed.binary_path.exists(), "binary extracted");

    // §6.2: ledger records the origin source name + url + digest
    let state = load_state(tmp);
    let rec = state.get("ping-pong").expect("ledger recorded");
    assert_eq!(rec.source, "test");
    assert_eq!(rec.source_url, src.url);
    assert_eq!(rec.sha256, hash);

    mock.assert_async().await;
}

// D3: the manifest's own sandbox hint replaces the old plugin-id special case
#[tokio::test]
async fn install_flows_manifest_sandbox_false_through() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive("network", r#", "sandbox": false"#);
    let url = format!("{}/network.zip", server.url());
    server
        .mock("GET", "/network.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    let (sk, pk_hex) = test_signer();
    let entry = signed_archive_entry(&sk, "network", &url, &hash, "0.1.0");
    let src = test_source("https://registry.example", Some(pk_hex));

    let installed = install(
        &[entry],
        "network",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert!(!installed.sandbox_hint, "manifest sandbox:false must win");
}

// Step 5: digest mismatch aborts before extraction touches anything
#[tokio::test]
async fn install_rejects_wrong_digest() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, _) = build_archive("ping-pong", "");
    let url = format!("{}/ping-pong.zip", server.url());
    server
        .mock("GET", "/ping-pong.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    let (sk, pk_hex) = test_signer();
    // signature binds the WRONG hash on purpose: entry claims deadbeef
    let mut entry = make_entry("ping-pong", "0.1.0", "*");
    entry.archive_url = url;
    entry.sha256 = "deadbeef".into();
    sign_entry(&sk, &mut entry);
    let src = test_source("https://registry.example", Some(pk_hex));

    let err = install(
        &[entry],
        "ping-pong",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("integrity check failed") && msg.contains("deadbeef"),
        "unexpected: {msg}"
    );
    // nothing leaked into the plugin dir
    assert!(!plugin_dir(Path::new("/nonexistent-tmp"))
        .join("ping-pong")
        .exists());
}

// Step 3: a configured key makes signatures mandatory, before any download
#[tokio::test]
async fn install_requires_signature_when_source_has_key() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive("ping-pong", "");
    let url = format!("{}/ping-pong.zip", server.url());
    // expect ZERO hits: refusal happens before request forgery can occur
    let mock = server
        .mock("GET", "/ping-pong.zip")
        .with_status(200)
        .with_body(archive)
        .expect(0)
        .create_async()
        .await;

    let (_sk, pk_hex) = test_signer(); // entry left UNSIGNED
    let mut unsigned_entry = make_entry("ping-pong", "0.1.0", "*");
    unsigned_entry.archive_url = url;
    unsigned_entry.sha256 = hash;
    let src = test_source("https://registry.example", Some(pk_hex));

    let err = install(
        &[unsigned_entry],
        "ping-pong",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    // empty/malformed sig and mismatched sig take different branches of
    // verify_entry_signature — both are the fail-closed refusal we want
    let msg = err.to_string();
    assert!(msg.contains("signature"), "unexpected: {msg}");
    mock.assert_async().await;
}

// §7.3-consented unsigned source: no signature check, but the digest gate
// still refuses tampered bytes
#[tokio::test]
async fn unsigned_source_skips_signature_but_keeps_digest_gate() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, real_hash) = build_archive("ping-pong", "");
    let url = format!("{}/ping-pong.zip", server.url());
    server
        .mock("GET", "/ping-pong.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    let mut entry = make_entry("ping-pong", "0.1.0", "*");
    entry.archive_url = url;
    entry.sha256 = real_hash; // correct digest, NO signature at all

    let src = test_source("https://registry.example", None);

    // happy path: unsigned content installs when the operator consented
    let installed = install(
        &[entry.clone()],
        "ping-pong",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(installed.version, "1.0.0");

    // digest gate still armed: same flow with a wrong claimed hash fails
    let mut bad = entry;
    bad.slug = "other".into();
    bad.sha256 = "deadbeef".into();
    let err = install(
        &[bad],
        "other",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("integrity check failed"),
        "unexpected: {err}"
    );
}

// ── D2 acceptance: no compat gate at install time ───────────────────────────

#[tokio::test]
async fn install_has_no_compat_gate_against_unreachable_kernel() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    // range demands kernel 99.0.0 — nothing local satisfies that; the
    // kernel (unreachable here) re-validates authoritatively at boot
    let (archive, hash) = build_archive("future-plugin", "");
    let url = format!("{}/future-plugin.zip", server.url());
    server
        .mock("GET", "/future-plugin.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    let (sk, pk_hex) = test_signer();
    let entry = signed_archive_entry(&sk, "future-plugin", &url, &hash, "99.0.0");
    let src = test_source("https://registry.example", Some(pk_hex));

    let installed = install(
        &[entry],
        "future-plugin",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(installed.slug, "future-plugin");
}

// ── R10-02 skip_reinstall ───────────────────────────────────────────────────

#[tokio::test]
async fn skip_reinstall_when_same_version_and_dir_present() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let dest = plugin_dir(tmp).join("ping-pong");
    fs::create_dir_all(&dest).unwrap();
    fs::write(
            dest.join("plugin.json"),
            r#"{"plugin_id":"ping-pong","version":"1.0.0","permissions":[],"binary":"ping-pong","kernel_compatibility_range":{"min":"0.1.0","max":"*"}}"#,
        )
        .unwrap();
    record_install(
        tmp,
        vynkor_manager::state::InstalledEntry {
            slug: "ping-pong".into(),
            version: "1.0.0".into(),
            sha256: "abc".into(),
            installed_at: 1,
            source_url: "https://registry.example".into(),
            source: "official".into(),
            tree_sha256: None,
            previous: None,
        },
    )
    .unwrap();

    let skipped = skip_reinstall(tmp, "ping-pong", "1.0.0", &dest).unwrap();
    assert_eq!(skipped.version, "1.0.0");
    assert!(skipped.sandbox_hint);
}

#[tokio::test]
async fn skip_reinstall_when_dir_missing_repairs_via_install() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    record_install(
        tmp,
        vynkor_manager::state::InstalledEntry {
            slug: "gone".into(),
            version: "1.0.0".into(),
            sha256: "abc".into(),
            installed_at: 1,
            source_url: "https://r.example".into(),
            source: "official".into(),
            tree_sha256: None,
            previous: None,
        },
    )
    .unwrap();
    let missing = plugin_dir(tmp).join("gone");
    assert!(skip_reinstall(tmp, "gone", "1.0.0", &missing).is_none());
}

#[tokio::test]
async fn skip_reinstall_on_version_bump() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let dest = plugin_dir(tmp).join("up");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("plugin.json"), "{}").unwrap();
    record_install(
        tmp,
        vynkor_manager::state::InstalledEntry {
            slug: "up".into(),
            version: "0.1.0".into(),
            sha256: "abc".into(),
            installed_at: 1,
            source_url: "https://r.example".into(),
            source: "official".into(),
            tree_sha256: None,
            previous: None,
        },
    )
    .unwrap();
    assert!(skip_reinstall(tmp, "up", "0.2.0", &dest).is_none());
}

// ── enable/disable against a real extracted tree (acceptance composition) ───

#[tokio::test]
async fn disable_enable_cycle_after_real_install() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive("cycler", "");
    let url = format!("{}/cycler.zip", server.url());
    server
        .mock("GET", "/cycler.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    let (sk, pk_hex) = test_signer();
    let entry = signed_archive_entry(&sk, "cycler", &url, &hash, "0.1.0");
    let src = test_source("https://registry.example", Some(pk_hex));
    install(
        &[entry],
        "cycler",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()),
    )
    .await
    .unwrap();

    // drop-in written by the caller (as V-06 will), then toggled
    let plugins_d = tmp.join("plugins.d");
    let installed = load_state(tmp).get("cycler").unwrap().clone();
    let params = vynkor_manager::dropin::DropinParams {
        slug: "cycler",
        plugin_id: "cycler",
        binary_path: &plugin_dir(tmp).join("cycler/cycler"),
        sandbox: true,
    };
    assert!(vynkor_manager::dropin::write_plugin_config(&plugins_d, &params).unwrap());

    assert_eq!(
        disable_plugin_config(&plugins_d, &installed.slug).unwrap(),
        Toggle::Toggled
    );
    assert!(!plugins_d.join("cycler.yaml").exists());
    assert!(plugins_d.join("cycler.yaml.disabled").exists());

    assert_eq!(
        enable_plugin_config(&plugins_d, &installed.slug).unwrap(),
        Toggle::Toggled
    );
    assert!(plugins_d.join("cycler.yaml").exists());
}

// ── extract_zip security battery (ported verbatim cases) ────────────────────

fn make_zip_raw(dest: &Path, entries: &[(&str, &[u8], Option<u32>)]) {
    let file = fs::File::create(dest).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, data, mode) in entries {
        // zip 2.x: writer-side permissions are unix_permissions()
        use zip::write::{ExtendedFileOptions, FileOptions};
        let mut opts: FileOptions<'_, ExtendedFileOptions> =
            FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        if let Some(m) = mode {
            opts = opts.unix_permissions(*m);
        }
        zip.start_file(*name, opts).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

#[test]
fn clean_zip_extracts() {
    let tmp = tempdir().unwrap();
    let (archive, _) = build_archive("clean", "");
    let arch_path = tmp.path().join("a.zip");
    fs::write(&arch_path, &archive).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    extract_zip(&arch_path, &out, MAX_EXTRACTED, MAX_ENTRIES, None).unwrap();
    assert!(out.join("plugin.json").exists());
    assert!(out.join("clean").exists());
}

#[test]
fn zip_slip_dotdot_rejected() {
    let tmp = tempdir().unwrap();
    make_zip_raw(
        &tmp.path().join("evil.zip"),
        &[("../escaped.txt", b"x", None)],
    );
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let err = extract_zip(
        &tmp.path().join("evil.zip"),
        &out,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        None,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("path traversal"),
        "unexpected: {err}"
    );
    assert!(!tmp.path().join("escaped.txt").exists(), "must not escape");
}

#[test]
fn zip_slip_absolute_path_rejected() {
    let tmp = tempdir().unwrap();
    make_zip_raw(
        &tmp.path().join("evil.zip"),
        &[("/etc/escaped.txt", b"x", None)],
    );
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let err = extract_zip(
        &tmp.path().join("evil.zip"),
        &out,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        None,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("path traversal"),
        "unexpected: {err}"
    );
}

#[test]
fn extraction_restores_exec_bit() {
    let tmp = tempdir().unwrap();
    make_zip_raw(
        &tmp.path().join("a.zip"),
        &[("bin", b"#!/bin/sh\n", Some(0o755))],
    );
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    extract_zip(
        &tmp.path().join("a.zip"),
        &out,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        None,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(out.join("bin")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "exec bit must survive extraction");
    }
}

#[test]
fn archive_with_excess_entries_rejected() {
    let tmp = tempdir().unwrap();
    make_zip_raw(
        &tmp.path().join("many.zip"),
        &(0..5)
            .map(|i| (format!("f{i}").leak() as &str, &b"x"[..], None))
            .collect::<Vec<_>>(),
    );
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let err = extract_zip(&tmp.path().join("many.zip"), &out, MAX_EXTRACTED, 3, None).unwrap_err();
    assert!(
        err.to_string().contains("exceeds max 3"),
        "unexpected: {err}"
    );
}

#[test]
fn zip_bomb_decompressed_size_capped() {
    let tmp = tempdir().unwrap();
    // 64 KiB of stored zeros vs a tiny cap — enforced on copied bytes
    make_zip_raw(
        &tmp.path().join("bomb.zip"),
        &[("zeros", &[0u8; 65536], None)],
    );
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let err = extract_zip(&tmp.path().join("bomb.zip"), &out, 1024, MAX_ENTRIES, None).unwrap_err();
    assert!(
        err.to_string().contains("decompressed size exceeds max"),
        "unexpected: {err}"
    );
}

// ── V-10 permission preview + confirmation gate ─────────────────────────────

fn preview_manifest() -> vynkor_wire::manifest::InstallManifest {
    serde_json::from_str(
        r#"{
        "plugin_id": "mixed",
        "version": "2.0.0",
        "permissions": ["storage", "network"],
        "binary": "bin",
        "kernel_compatibility_range": {"min": "0.1.0", "max": "*"},
        "actions": [
            "legacy-act",
            {"name": "fetch", "permission": "storage"},
            {"name": "exec"}
        ]
    }"#,
    )
    .unwrap()
}

#[test]
fn preview_lists_permissions_and_every_action_requirement() {
    let out = format_permission_preview(&preview_manifest());
    assert!(
        out.contains("permissions: storage, network"),
        "unexpected: {out}"
    );
    // legacy string action → unrestricted
    assert!(
        out.contains("legacy-act -> unrestricted"),
        "unexpected: {out}"
    );
    // v2 with a permission → the permission
    assert!(out.contains("fetch -> storage"), "unexpected: {out}");
    // v2 without one → unrestricted
    assert!(out.contains("exec -> unrestricted"), "unexpected: {out}");
}

#[test]
fn preview_of_empty_manifest_says_none() {
    let m: vynkor_wire::manifest::InstallManifest = serde_json::from_str(
        r#"{
        "plugin_id": "bare",
        "version": "1.0.0",
        "permissions": [],
        "binary": "b",
        "kernel_compatibility_range": {"min": "0.1.0", "max": "*"}
    }"#,
    )
    .unwrap();
    let out = format_permission_preview(&m);
    assert_eq!(out, "permissions: (none)\n");
}

// refusal aborts exactly like failed validation: dest/bak untouched, ledger
// unrecorded, no drop-in, staging cleaned — and the gate provably fires
// BEFORE the swap with the real parsed manifest in hand
#[tokio::test]
async fn install_gate_refusal_leaves_zero_trace() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive(
        "guarded",
        r#", "actions":[{"name":"fetch","permission":"storage"}]"#,
    );
    let url = format!("{}/guarded.zip", server.url());
    server
        .mock("GET", "/guarded.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    let (sk, pk_hex) = test_signer();
    let entry = signed_archive_entry(&sk, "guarded", &url, &hash, "0.1.0");
    let src = test_source("https://registry.example", Some(pk_hex));

    let base = plugin_dir(tmp);
    let dest = base.join("guarded");
    let err = install(
        &[entry],
        "guarded",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |manifest| {
            // preview uses the REAL parsed manifest of the staged copy:
            // the v2 action requirement survived parse + validation
            let req = manifest
                .actions
                .as_ref()
                .and_then(|a| a.first())
                .and_then(|s| s.permission());
            assert_eq!(req, Some("storage"));
            // gate ordering: nothing user-visible exists yet
            assert!(!dest.exists(), "gate must fire before the swap");
            Err(VynmError::Internal("operator said no".into()))
        },
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("operator said no"));
    assert!(!dest.exists(), "dest untouched");
    assert!(!base.join("guarded.bak").exists(), "no bak left behind");
    assert!(
        load_state(tmp).get("guarded").is_none(),
        "ledger not recorded"
    );
    assert!(
        !tmp.join("plugins.d").join("guarded.yaml").exists(),
        "no drop-in written"
    );
    assert!(
        !base.join(".install-tmp-guarded").exists(),
        "staging cleaned"
    );
}

// §7.3 consent Yes + V-10 gate Yes: worst-case two-question flow completes
#[tokio::test]
async fn unsigned_consent_then_gate_yes_still_installs() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive("two-ask", "");
    let url = format!("{}/two-ask.zip", server.url());
    server
        .mock("GET", "/two-ask.zip")
        .with_status(200)
        .with_body(archive)
        .create_async()
        .await;

    // unsigned entry on an unsigned-consented source: consent prompt would
    // fire at fetch time; here unit-level it means no public_key configured
    let mut entry = make_entry("two-ask", "0.1.0", "*");
    entry.archive_url = url;
    entry.sha256 = hash;
    let mut src = test_source("https://registry.example", None);
    src.allow_unsigned = true;

    let installed = install(
        &[entry],
        "two-ask",
        &src,
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        |_| Ok(()), // gate answered yes
    )
    .await
    .unwrap();

    assert_eq!(installed.slug, "two-ask");
    assert!(load_state(tmp).get("two-ask").is_some(), "ledger recorded");
}

// ── V-15 archive installs (local zip / direct URL) ──────────────────────────

#[test]
fn local_archive_notice_names_the_missing_guarantees_and_digest() {
    let n = format_local_archive_notice("abc123");
    assert!(n.contains("no registry signature"), "unexpected: {n}");
    assert!(
        n.contains("published-sha256 guarantee applies"),
        "unexpected: {n}"
    );
    assert!(n.contains("computed sha256: abc123"), "unexpected: {n}");
}

// happy path: --yes variant — gate fires with the real staged manifest,
// ledger records source "local" + the path, drop-in written by the caller
#[tokio::test]
async fn archive_local_zip_happy_path() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let (archive, hash) = build_archive("local-dev", "");
    let zip_path = tmp.join("local-dev.zip");
    fs::write(&zip_path, &archive).unwrap();

    let installed = install_archive(
        &ArchiveOrigin::LocalPath(zip_path.clone()),
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        false, // allow_http irrelevant for local files
        |manifest| {
            // V-10 gate fired with the parsed manifest of the staged copy
            assert_eq!(manifest.plugin_id, "local-dev");
            Ok(())
        },
    )
    .await
    .unwrap();

    assert_eq!(installed.slug, "local-dev");
    assert_eq!(installed.version, "1.0.0");
    assert!(installed.binary_path.exists());

    let rec = load_state(tmp)
        .get("local-dev")
        .expect("ledger recorded")
        .clone();
    assert_eq!(rec.source, "local");
    assert_eq!(rec.source_url, zip_path.display().to_string());
    assert_eq!(rec.sha256, hash);
    assert!(rec.tree_sha256.is_some(), "V-13 digest still recorded");

    // drop-in written by the caller, exactly like registry installs
    let params = vynkor_manager::dropin::DropinParams {
        slug: &installed.slug,
        plugin_id: &installed.plugin_id,
        binary_path: &installed.binary_path,
        sandbox: true,
    };
    assert!(vynkor_manager::dropin::write_plugin_config(&tmp.join("plugins.d"), &params).unwrap());
    assert!(tmp.join("plugins.d").join("local-dev.yaml").exists());
}

// malformed manifest inside a LOCAL archive → refused, zero trace
#[tokio::test]
async fn archive_malformed_manifest_refused_with_zero_trace() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();

    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("plugin.json", opts).unwrap();
        zip.write_all(br#"{"plugin_id":"broken","version":"","permissions":[]}"#)
            .unwrap();
        zip.finish().unwrap();
    }
    let zip_path = tmp.join("broken.zip");
    fs::write(&zip_path, buf.into_inner()).unwrap();

    let err = install_archive(
        &ArchiveOrigin::LocalPath(zip_path),
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        false,
        |_| panic!("gate must not fire on an invalid manifest"),
    )
    .await
    .unwrap_err();

    assert!(!err.to_string().is_empty());
    let base = plugin_dir(tmp);
    assert!(!base.join("broken").exists(), "dest untouched");
    assert!(
        !base.join(".install-tmp-broken").exists(),
        "staging cleaned"
    );
    assert!(
        load_state(tmp).get("broken").is_none(),
        "ledger not recorded"
    );
}

// zip-slip inside a LOCAL archive → refused verbatim; the boundary holds
// regardless of where the bytes came from
#[tokio::test]
async fn archive_zip_slip_in_local_file_refused_verbatim() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    make_zip_raw(
        &tmp.join("evil-local.zip"),
        &[
            (
                "plugin.json",
                br#"{"plugin_id":"evil","version":"1.0.0","permissions":[],"binary":"evil","kernel_compatibility_range":{"min":"0.1.0","max":"*"}}"#
                    as &[u8],
                None,
            ),
            ("../escaped.txt", b"x", None),
        ],
    );

    let err = install_archive(
        &ArchiveOrigin::LocalPath(tmp.join("evil-local.zip")),
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        false,
        |_| Ok(()),
    )
    .await
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("path traversal detected in entry '../escaped.txt'"),
        "refusal must be verbatim: {msg}"
    );
    assert!(
        !tmp.parent().unwrap().join("escaped.txt").exists()
            && !plugin_dir(tmp).join("escaped.txt").exists(),
        "must not escape anywhere"
    );
}

// D8 for direct URLs: http:// refused naming --allow-unsigned BEFORE any
// request moves; with the flag it downloads and installs
#[tokio::test]
async fn direct_http_url_refused_without_allow_unsigned_then_installs_with_it() {
    let sandbox = Sandbox::new();
    let tmp = sandbox.dir.path();
    let mut server = mockito::Server::new_async().await;
    let (archive, hash) = build_archive("fetched", "");
    let url = format!("{}/fetched.zip", server.url());
    // first phase must never hit the wire; second phase hits exactly once
    let mock = server
        .mock("GET", "/fetched.zip")
        .with_status(200)
        .with_body(archive)
        .expect(1)
        .create_async()
        .await;

    let err = install_archive(
        &ArchiveOrigin::DirectUrl(url.clone()),
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        false, // no consent
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("http://") && msg.contains("--allow-unsigned"),
        "refusal must name the exact knob: {msg}"
    );

    let installed = install_archive(
        &ArchiveOrigin::DirectUrl(url),
        tmp,
        MAX_ARCHIVE,
        MAX_EXTRACTED,
        MAX_ENTRIES,
        true, // the flag IS the consent — there is no source config here
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(installed.slug, "fetched");

    let rec = load_state(tmp)
        .get("fetched")
        .expect("ledger recorded")
        .clone();
    assert_eq!(rec.source, "local");
    assert_eq!(rec.sha256, hash);
    mock.assert_async().await;
}
