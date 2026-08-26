use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::{verify_entry, VerifyStatus};
use crate::installer::tree_digest;
use crate::state::InstalledEntry;

fn entry(tree: Option<&str>) -> InstalledEntry {
    InstalledEntry {
        slug: "demo".into(),
        version: "1.0.0".into(),
        sha256: "archive-digest".into(),
        installed_at: 1,
        source_url: "https://registry.example".into(),
        source: "official".into(),
        tree_sha256: tree.map(str::to_string),
        previous: None,
    }
}

fn make_tree(root: &std::path::Path) -> std::path::PathBuf {
    let dir = root.join("demo");
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("plugin.json"), "{}").unwrap();
    let bin = dir.join("demo");
    fs::write(&bin, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

// ── tree_digest canonicalization ────────────────────────────────────────────

#[test]
fn digest_is_deterministic_and_content_sensitive() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = make_tree(tmp.path());
    let a = tree_digest(&dir).unwrap();
    let b = tree_digest(&dir).unwrap();
    assert_eq!(a, b, "same tree must hash identically");
    assert_eq!(a.len(), 64, "lowercase hex sha256");

    fs::write(dir.join("plugin.json"), "{ }").unwrap();
    assert_ne!(
        tree_digest(&dir).unwrap(),
        a,
        "content change must change the digest"
    );
}

#[test]
fn digest_covers_mode_and_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = make_tree(tmp.path());
    let base = tree_digest(&dir).unwrap();

    // exec-bit flip alone must trip the digest
    let bin = dir.join("demo");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o644)).unwrap();
    assert_ne!(tree_digest(&dir).unwrap(), base, "mode is part of digest");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

    // rename within the same content set → different relpath stream
    fs::rename(dir.join("plugin.json"), dir.join("renamed.json")).unwrap();
    assert_ne!(
        tree_digest(&dir).unwrap(),
        base,
        "relpath is part of digest"
    );
}

#[test]
fn digest_ignores_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = make_tree(tmp.path());
    let base = tree_digest(&dir).unwrap();
    std::os::unix::fs::symlink("/etc", dir.join("evil")).unwrap();
    assert_eq!(
        tree_digest(&dir).unwrap(),
        base,
        "symlinks never enter the digest (extract_zip never creates them)"
    );
}

#[test]
fn digest_of_missing_dir_errors() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(tree_digest(&tmp.path().join("nope")).is_err());
}

// ── verify_entry status matrix ──────────────────────────────────────────────

#[test]
fn entry_without_recorded_digest_is_unknown_baseline() {
    let status = verify_entry(&entry(None), std::path::Path::new("/nonexistent"));
    assert_eq!(status, VerifyStatus::UnknownBaseline);
}

#[test]
fn missing_dir_reports_missing_with_path() {
    let tmp = tempfile::tempdir().unwrap();
    let status = verify_entry(
        &entry(Some("deadbeef")),
        tmp.path(), // demo/ does not exist under here
    );
    match status {
        VerifyStatus::Missing(p) => assert!(p.ends_with("demo"), "{p}"),
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[test]
fn matching_and_diverging_trees() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = make_tree(tmp.path());
    let good = entry(Some(&tree_digest(&dir).unwrap()));

    assert_eq!(verify_entry(&good, tmp.path()), VerifyStatus::Ok);

    fs::write(dir.join("demo"), b"#!/bin/sh\ntouch /tmp/x\n").unwrap();
    let tampered = verify_entry(&good, tmp.path());
    match tampered {
        VerifyStatus::Tampered { expected, actual } => {
            assert_ne!(expected, actual);
            assert_eq!(expected.len(), 64);
            assert_eq!(actual.len(), 64);
        }
        other => panic!("expected Tampered, got {other:?}"),
    }
}
