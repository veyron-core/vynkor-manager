use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use tempfile::tempdir;

use super::{latest_version, run, PackageOpts};
use crate::error::VynmError;
use crate::registry::verify_entry_signature;
use vynkor_wire::manifest::{default_resolver, validate_manifest};

fn write_plugin_dir(dir: &Path, slug: &str, version: &str, files_extra: &str) {
    fs::create_dir_all(dir).unwrap();
    let binary = format!("#!/bin/sh\necho {version}\n");
    fs::write(dir.join(slug), binary).unwrap();
    let json = format!(
        r#"{{"plugin_id":"{slug}","version":"{version}","permissions":[],"binary":"{slug}","kernel_compatibility_range":{{"min":"0.1.0","max":"*"}}{files_extra}}}"#
    );
    fs::write(dir.join("plugin.json"), json).unwrap();
}

fn default_tags() -> &'static [String] {
    static TAGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    TAGS.get_or_init(|| vec!["t1".into(), "t2".into()])
}

fn opts<'a>(
    dir: &'a Path,
    repo_root: &'a Path,
    key: Option<&'a Path>,
    name: &'a str,
) -> PackageOpts<'a> {
    PackageOpts {
        dir,
        repo_root,
        name,
        description: "test plugin",
        category: "utility",
        tags: default_tags(),
        status: "stable",
        source_url: "",
        key,
        force: false,
    }
}

fn seed_file(dir: &Path, seed: &[u8; 32]) -> std::path::PathBuf {
    let path = dir.join("signing.key");
    fs::write(&path, hex_encode(seed)).unwrap();
    path
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── full signed pipeline: dist layout + registry upsert + self-verifying sig ──

#[test]
fn packages_dist_layout_and_upserts_signed_entry() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("demo");
    write_plugin_dir(&plugin_dir, "demo", "0.1.0", "");

    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let key_path = seed_file(tmp.path(), &sk.to_bytes());
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    run(opts(&plugin_dir, &repo_root, Some(&key_path), "Demo")).unwrap();

    // dist layout: zip + checksum + browse copy + signature + latest.json
    let version_dir = repo_root.join("dist/demo/versions/0.1.0");
    let archive = version_dir.join("demo-0.1.0.zip");
    assert!(archive.is_file(), "zip missing");

    let expected_sha = hex_encode(&{
        use sha2::{Digest, Sha256};
        Sha256::digest(fs::read(&archive).unwrap())
    });
    assert_eq!(
        fs::read_to_string(version_dir.join("checksum.sha256")).unwrap(),
        format!("{expected_sha}  demo-0.1.0.zip\n")
    );
    assert_eq!(
        fs::read(version_dir.join("plugin.json")).unwrap(),
        fs::read(plugin_dir.join("plugin.json")).unwrap()
    );

    // the zip carries FLAT entries (basename only) and unpacks to a valid tree
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(fs::read(&archive).unwrap())).unwrap();
    let mut names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["demo", "plugin.json"]);
    let extracted = tmp.path().join("extracted");
    fs::create_dir_all(&extracted).unwrap();
    zip.extract(&extracted).unwrap();
    let manifest =
        validate_manifest(&extracted.join("plugin.json"), None, default_resolver).unwrap();
    assert_eq!(manifest.plugin_id, "demo");
    assert!(extracted.join("demo").is_file());

    // signature.sig verifies against the derived public key over the SAME
    // canonical form the installer will check
    let sig = fs::read_to_string(version_dir.join("signature.sig")).unwrap();
    assert_eq!(sig.trim().len(), 128);
    let pk_hex = hex_encode(&sk.verifying_key().to_bytes());
    let mut entry = crate::sign::entry_from_fields(
        "demo",
        "0.1.0",
        &expected_sha,
        "stable",
        "dist/demo/versions/0.1.0/demo-0.1.0.zip",
        "0.1.0",
        "*",
    );
    entry.signature = sig.trim().to_string();
    verify_entry_signature(&entry, &pk_hex).unwrap();

    // latest.json points at this (only) version
    let latest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo_root.join("dist/demo/latest.json")).unwrap())
            .unwrap();
    assert_eq!(latest["version"], "0.1.0");

    // registry.json: canonical top-level order meta → revoked → slugs, and
    // the version entry mirrors what was signed
    let reg: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo_root.join("registry.json")).unwrap())
            .unwrap();
    let map = reg.as_object().unwrap();
    let keys: Vec<&String> = map.keys().collect();
    assert_eq!(keys.len(), 3);
    assert_eq!(map.keys().next().unwrap(), "meta");
    assert_eq!(map.keys().nth(1).unwrap(), "revoked");
    assert_eq!(map.keys().nth(2).unwrap(), "demo");
    assert_eq!(reg["meta"]["apiVersion"], 2);
    assert_eq!(reg["demo"]["name"], "Demo");
    assert_eq!(reg["demo"]["tags"][0], "t1");
    assert_eq!(
        reg["demo"]["versions"]["0.1.0"]["archive_url"],
        "dist/demo/versions/0.1.0/demo-0.1.0.zip"
    );
    assert_eq!(reg["demo"]["versions"]["0.1.0"]["sha256"], expected_sha);
    assert_eq!(reg["demo"]["versions"]["0.1.0"]["signature"], sig.trim());
}

// ── unsigned packaging: empty signature, no .sig file ───────────────────────

#[test]
fn unsigned_package_records_empty_signature() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("bare");
    write_plugin_dir(&plugin_dir, "bare", "1.0.0", "");
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    run(opts(&plugin_dir, &repo_root, None, "Bare")).unwrap();

    let version_dir = repo_root.join("dist/bare/versions/1.0.0");
    assert!(!version_dir.join("signature.sig").exists());
    let reg: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo_root.join("registry.json")).unwrap())
            .unwrap();
    assert_eq!(reg["bare"]["versions"]["1.0.0"]["signature"], "");
}

// ── refusals ─────────────────────────────────────────────────────────────────

#[test]
fn refuses_existing_archive_without_force_and_overwrites_with_it() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("dup");
    write_plugin_dir(&plugin_dir, "dup", "0.3.0", "");
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    run(opts(&plugin_dir, &repo_root, None, "Dup")).unwrap();

    let err = run(opts(&plugin_dir, &repo_root, None, "Dup")).unwrap_err();
    assert!(err.to_string().contains("--force"), "{err}");

    let mut forced = opts(&plugin_dir, &repo_root, None, "Dup");
    forced.force = true;
    forced.name = "Renamed";
    run(forced).unwrap();
    let reg: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo_root.join("registry.json")).unwrap())
            .unwrap();
    assert_eq!(reg["dup"]["name"], "Renamed");
    assert_eq!(reg["dup"]["versions"].as_object().unwrap().len(), 1);
}

#[test]
fn files_allowlist_must_cover_binary_and_plugin_json() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("partial");
    write_plugin_dir(
        &plugin_dir,
        "partial",
        "0.1.0",
        r#","files":["plugin.json"]"#,
    );
    let err = run(opts(&plugin_dir, tmp.path(), None, "Partial")).unwrap_err();
    assert!(err.to_string().contains("must include"), "{err}");
}

#[test]
fn files_allowlist_packages_declared_set_flat() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("full");
    write_plugin_dir(
        &plugin_dir,
        "full",
        "0.2.0",
        r#","files":["plugin.json","full","assets/readme.txt"]"#,
    );
    fs::create_dir_all(plugin_dir.join("assets")).unwrap();
    fs::write(plugin_dir.join("assets/readme.txt"), "hi").unwrap();

    run(opts(&plugin_dir, tmp.path(), None, "Full")).unwrap();
    let archive = tmp.path().join("dist/full/versions/0.2.0/full-0.2.0.zip");
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(fs::read(archive).unwrap())).unwrap();
    let mut names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["full", "plugin.json", "readme.txt"]);
}

// ── upsert semantics: other slugs + revoked preserved, versions merge ────────

#[test]
fn upsert_preserves_other_slugs_revoked_and_merges_versions() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("two");
    write_plugin_dir(&plugin_dir, "two", "0.2.0", "");
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    let existing = r#"{
  "meta": {"apiVersion": 2, "lastUpdated": "2000-01-01"},
  "revoked": ["evil@9.9.9"],
  "aaa": {"name": "First", "description": "", "category": "utility", "tags": [], "status": "stable", "source_url": "", "versions": {"0.1.0": {"archive_url": "x.zip", "sha256": "aa", "signature": "", "min_kernel_version": "0.1.0", "max_kernel_version": "*"}}},
  "two": {"name": "Old name", "description": "", "category": "utility", "tags": [], "status": "stable", "source_url": "https://keep/me", "versions": {"0.1.0": {"archive_url": "old.zip", "sha256": "bb", "signature": "", "min_kernel_version": "0.1.0", "max_kernel_version": "*"}}}
}"#;
    fs::write(repo_root.join("registry.json"), existing).unwrap();

    run(opts(&plugin_dir, &repo_root, None, "Two")).unwrap();

    let raw = fs::read_to_string(repo_root.join("registry.json")).unwrap();
    let reg: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(reg["meta"]["lastUpdated"], super::today());
    assert_eq!(reg["revoked"][0], "evil@9.9.9");
    assert_eq!(reg["aaa"]["name"], "First");
    // source_url we own is empty by default BUT the carried-over value wins
    // only when the caller leaves it empty — here default "" overwrote it.
    assert_eq!(reg["two"]["source_url"], "");
    let versions = reg["two"]["versions"].as_object().unwrap();
    assert_eq!(versions.len(), 2, "0.1.0 kept alongside 0.2.0");
    assert!(versions.contains_key("0.1.0"));

    // latest.json picks the highest semver across registered versions
    let latest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo_root.join("dist/two/latest.json")).unwrap())
            .unwrap();
    assert_eq!(latest["version"], "0.2.0");

    // canonical top-level ordering survives: meta, revoked, aaa, two
    let meta_pos = raw.find("\"meta\"").unwrap();
    let revoked_pos = raw.find("\"revoked\"").unwrap();
    let aaa_pos = raw.find("\"aaa\"").unwrap();
    let two_pos = raw.find("\"two\":").unwrap();
    assert!(meta_pos < revoked_pos && revoked_pos < aaa_pos && aaa_pos < two_pos);
}

// ── source archive: <slug>-src/ members, skipped for non-Rust dirs ──────────

#[test]
fn src_zip_carries_prefixed_sources_when_cargo_present() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("rusty");
    write_plugin_dir(&plugin_dir, "rusty", "0.4.0", "");
    fs::write(plugin_dir.join("Cargo.toml"), "[package]\nname=\"rusty\"\n").unwrap();
    fs::create_dir_all(plugin_dir.join("src/util")).unwrap();
    fs::write(plugin_dir.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(plugin_dir.join("src/util/mod.rs"), "// util\n").unwrap();
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    run(opts(&plugin_dir, &repo_root, None, "Rusty")).unwrap();

    let version_dir = repo_root.join("dist/rusty/versions/0.4.0");
    let src_zip = version_dir.join("rusty-0.4.0-src.zip");
    assert!(src_zip.is_file());
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(fs::read(src_zip).unwrap())).unwrap();
    let mut names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "rusty-src/Cargo.toml",
            "rusty-src/plugin.json",
            "rusty-src/src/main.rs",
            "rusty-src/src/util/mod.rs",
        ]
    );
}

#[test]
fn src_zip_skipped_without_cargo_and_src() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("plain");
    write_plugin_dir(&plugin_dir, "plain", "0.1.0", "");
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    run(opts(&plugin_dir, &repo_root, None, "Plain")).unwrap();
    assert!(!repo_root
        .join("dist/plain/versions/0.1.0/plain-0.1.0-src.zip")
        .exists());
}

#[test]
fn existing_src_zip_refused_without_force_even_after_binary_removed() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("both");
    write_plugin_dir(&plugin_dir, "both", "0.6.0", "");
    fs::write(plugin_dir.join("Cargo.toml"), "[package]\n").unwrap();
    fs::create_dir_all(plugin_dir.join("src")).unwrap();
    fs::write(plugin_dir.join("src/lib.rs"), "").unwrap();
    let repo_root = tmp.path().join("repo");
    fs::create_dir_all(&repo_root).unwrap();

    run(opts(&plugin_dir, &repo_root, None, "Both")).unwrap();
    // guard scenario: binary archive gone, src zip still in place
    fs::remove_file(repo_root.join("dist/both/versions/0.6.0/both-0.6.0.zip")).unwrap();
    let err = run(opts(&plugin_dir, &repo_root, None, "Both")).unwrap_err();
    assert!(err.to_string().contains("--force"), "{err}");
}

// ── latest_version helper ────────────────────────────────────────────────────

#[test]
fn latest_version_picks_highest_semver_ignoring_garbage() {
    let existing = ["0.1.0", "not-a-version", "0.2.0"];
    assert_eq!(latest_version(&existing, "0.1.5"), "0.2.0");
    let garbage = ["banana"];
    assert_eq!(latest_version(&garbage, "0.4.4"), "0.4.4");
}

// ── input validation ─────────────────────────────────────────────────────────

#[test]
fn missing_binary_or_bad_manifest_are_invalid_input() {
    let tmp = tempdir().unwrap();
    let plugin_dir = tmp.path().join("nobin");
    write_plugin_dir(&plugin_dir, "nobin", "0.1.0", "");
    fs::remove_file(plugin_dir.join("nobin")).unwrap();
    let err = run(opts(&plugin_dir, tmp.path(), None, "NoBin")).unwrap_err();
    assert!(matches!(err, VynmError::InvalidInput(_)), "{err:?}");

    let bad = tmp.path().join("badman");
    fs::create_dir_all(&bad).unwrap();
    fs::write(bad.join("plugin.json"), "{\"plugin_id\":\"x\"}").unwrap();
    let err = run(opts(&bad, tmp.path(), None, "Bad")).unwrap_err();
    assert!(err.to_string().contains("invalid plugin.json"), "{err}");
}
