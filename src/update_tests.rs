use super::*;

// ── strict semver three-way classification ──────────────────────────────────

#[test]
fn cmp_versions_pins_all_three_outcomes() {
    use SemVerCmp::*;
    assert_eq!(cmp_versions("1.0.0", "1.2.0"), Ok(Newer));
    assert_eq!(cmp_versions("1.2.0", "1.0.0"), Ok(Older));
    assert_eq!(cmp_versions("1.2.0", "1.2.0"), Ok(Equal));
    // prerelease ordering follows semver rules
    assert_eq!(cmp_versions("1.0.0", "1.0.0-rc.1"), Ok(Older));
    assert_eq!(cmp_versions("1.0.0-rc.1", "1.0.0"), Ok(Newer));
}

#[test]
fn cmp_versions_never_guesses_on_unparsable_sides() {
    let err = cmp_versions("v1", "2.0.0").unwrap_err();
    assert!(err.contains("installed version 'v1'"), "{err}");
    let err = cmp_versions("1.0.0", "banana").unwrap_err();
    assert!(err.contains("registry version 'banana'"), "{err}");
}

// ── availability picking over multi-entry documents ─────────────────────────

use crate::registry::RegistryEntry;

fn doc_entry(slug: &str, version: &str) -> RegistryEntry {
    RegistryEntry {
        id: slug.into(),
        slug: slug.into(),
        name: slug.into(),
        description: String::new(),
        version: version.into(),
        permissions: vec![],
        archive_url: format!("/{slug}.zip"),
        source_url: String::new(),
        sha256: "deadbeef".into(),
        min_kernel_version: "0.1.0".into(),
        max_kernel_version: "*".into(),
        signature: String::new(),
        status: "stable".into(),
    }
}

#[test]
fn pick_available_selects_max_semver_and_skips_revoked() {
    let mut doc = vec![
        doc_entry("db", "1.0.0"),
        doc_entry("db", "1.5.0"),
        doc_entry("db", "1.2.0"),
    ];
    let (_, sha) = pick_available(&doc, "db").unwrap().unwrap();
    assert_eq!(sha, "deadbeef", "sha comes straight from the winning entry");

    doc.push(RegistryEntry {
        version: "9.9.9".into(),
        status: "revoked".into(),
        ..doc_entry("db", "9.9.9")
    });
    let (version, _) = pick_available(&doc, "db").unwrap().unwrap();
    assert_eq!(version, "1.5.0", "revoked entries never count as available");
}

#[test]
fn pick_available_distinguishes_miss_from_unparsable() {
    assert!(pick_available(&[], "ghost").unwrap().is_none());
    let doc = vec![doc_entry("db", "not-semver")];
    let err = pick_available(&doc, "db").unwrap_err();
    assert!(err.contains("none parse as semver"), "{err}");
}

// ── batch confirmation matrix (V-10 pattern, ONE prompt for N updates) ──────

#[test]
fn confirm_mode_pins_every_branch() {
    use ConfirmMode::*;
    assert_eq!(confirm_mode(true, true), AutoYes);
    assert_eq!(confirm_mode(true, false), AutoYes);
    assert_eq!(confirm_mode(false, true), Interactive);
    assert_eq!(
        confirm_mode(false, false),
        NonInteractiveRefusal,
        "non-TTY without -y must refuse"
    );
}

#[test]
fn short_sha_truncates_for_display() {
    assert_eq!(short_sha("abcdef1234567890"), "abcdef12");
    assert_eq!(short_sha(""), "");
}

// ── V-16: outdated --json shape ─────────────────────────────────────────────

fn row_of(slug: &str, installed: &str, available: Option<&str>, kind: RowKind) -> Row {
    Row {
        slug: slug.into(),
        installed_version: installed.into(),
        installed_sha256: "deadbeef".into(),
        source_name: "official".into(),
        available_version: available.map(str::to_string),
        available_sha256: None,
        kind,
    }
}

#[test]
fn render_outdated_json_carries_status_and_versions() {
    let rows = vec![
        row_of("db", "1.0.0", Some("2.0.0"), RowKind::Outdated),
        row_of("logger", "3.0.0", Some("3.0.0"), RowKind::UpToDate),
    ];
    let parsed: serde_json::Value = serde_json::from_str(&render_outdated_json(&rows)).unwrap();
    assert_eq!(parsed[0]["slug"], "db");
    assert_eq!(parsed[0]["installed_version"], "1.0.0");
    assert_eq!(parsed[0]["available_version"], "2.0.0");
    assert_eq!(parsed[0]["source"], "official");
    assert_eq!(parsed[0]["status"], "OUTDATED");
    assert_eq!(parsed[1]["status"], "ok");

    let empty = render_outdated_json(&[]);
    assert_eq!(empty.trim(), "[]", "no rows serialize as an empty array");
}
