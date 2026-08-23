use std::fs;
use std::path::Path;

use tempfile::tempdir;

use vynkor_manager::state::{
    format_ts, load_state, record_install, remove_record, save_state, InstalledEntry,
    LEDGER_SCHEMA_VERSION,
};

fn entry(slug: &str, version: &str) -> InstalledEntry {
    InstalledEntry {
        slug: slug.into(),
        version: version.into(),
        sha256: "abc123".into(),
        installed_at: 1_700_000_000,
        source_url: "https://registry.example".into(),
        source: "official".into(),
        tree_sha256: None,
    }
}

// state_dir honours VYNM_STATE_DIR — every test runs inside it.
fn with_state_dir(f: impl FnOnce(&Path)) {
    let tmp = tempdir().unwrap();
    temp_env::with_var("VYNM_STATE_DIR", Some(tmp.path().to_str().unwrap()), || {
        f(tmp.path())
    });
}

#[test]
fn load_state_missing_file_is_empty() {
    with_state_dir(|_| {
        let state = load_state(Path::new("/nonexistent-tmp"));
        assert!(state.entries.is_empty());
    });
}

#[test]
fn record_then_load_roundtrips_entry() {
    with_state_dir(|_| {
        record_install(Path::new("/nonexistent-tmp"), entry("ping-pong", "0.1.0")).unwrap();
        let state = load_state(Path::new("/nonexistent-tmp"));
        let got = state.get("ping-pong").unwrap();
        assert_eq!(got.version, "0.1.0");
        assert_eq!(got.sha256, "abc123");
        assert_eq!(got.source_url, "https://registry.example");
        assert_eq!(got.installed_at, 1_700_000_000);
        assert_eq!(got.source, "official");
    });
}

#[test]
fn record_upserts_by_slug() {
    with_state_dir(|_| {
        record_install(Path::new("/nonexistent-tmp"), entry("network", "0.1.0")).unwrap();
        record_install(Path::new("/nonexistent-tmp"), entry("network", "0.2.0")).unwrap();
        let state = load_state(Path::new("/nonexistent-tmp"));
        assert_eq!(state.entries.len(), 1, "one record per slug");
        assert_eq!(state.get("network").unwrap().version, "0.2.0");
    });
}

#[test]
fn remove_record_deletes_entry() {
    with_state_dir(|_| {
        record_install(Path::new("/nonexistent-tmp"), entry("ai", "1.0.0")).unwrap();
        let removed = remove_record(Path::new("/nonexistent-tmp"), "ai").unwrap();
        assert_eq!(removed.unwrap().version, "1.0.0");
        assert!(load_state(Path::new("/nonexistent-tmp"))
            .get("ai")
            .is_none());
    });
}

#[test]
fn remove_untracked_slug_returns_none_without_writing() {
    with_state_dir(|dir| {
        let removed = remove_record(Path::new("/nonexistent-tmp"), "ghost").unwrap();
        assert!(removed.is_none());
        assert!(
            !dir.join("installed.json").exists(),
            "no-op remove writes nothing"
        );
    });
}

#[test]
fn save_state_writes_pretty_json() {
    with_state_dir(|dir| {
        let mut state = vynkor_manager::state::InstalledState::default();
        state.entries.push(entry("db", "0.1.0"));
        save_state(Path::new("/nonexistent-tmp"), &state).unwrap();
        let raw = fs::read_to_string(dir.join("installed.json")).unwrap();
        assert!(raw.contains("  \"slug\""), "expected pretty JSON:\n{raw}");
        let parsed: vynkor_manager::state::InstalledState = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.get("db").unwrap().slug, "db");
    });
}

// fresh writes carry the current schema version explicitly
#[test]
fn save_state_persists_current_schema_version() {
    with_state_dir(|dir| {
        let mut state = vynkor_manager::state::InstalledState::default();
        state.entries.push(entry("db", "0.1.0"));
        save_state(Path::new("/nonexistent-tmp"), &state).unwrap();
        let raw = fs::read_to_string(dir.join("installed.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            parsed["schema_version"].as_u64(),
            Some(LEDGER_SCHEMA_VERSION as u64)
        );
    });
}

#[test]
fn corrupt_state_file_loads_empty() {
    with_state_dir(|dir| {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("installed.json"), "{ not json").unwrap();
        assert!(load_state(Path::new("/nonexistent-tmp")).entries.is_empty());
    });
}

// §6.2 back-compat: a pre-v2 ledger (no schema_version, no per-entry source)
// reads cleanly — source defaults to "official" and the version normalizes
// so the next save persists the current schema.
#[test]
fn legacy_v1_ledger_reads_with_official_source() {
    with_state_dir(|dir| {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("installed.json"),
            r#"{
  "entries": [
    {
      "slug": "db",
      "version": "0.1.0",
      "sha256": "abc123",
      "installed_at": 1700000000,
      "source_url": "https://registry.example"
    }
  ]
}"#,
        )
        .unwrap();

        let state = load_state(Path::new("/nonexistent-tmp"));
        let got = state.get("db").expect("legacy entry loaded");
        assert_eq!(got.source, "official");
        assert_eq!(state.schema_version, LEDGER_SCHEMA_VERSION);

        // round-trip: next write persists the migrated shape
        record_install(Path::new("/nonexistent-tmp"), entry("ai", "2.0.0")).unwrap();
        let raw = fs::read_to_string(dir.join("installed.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            parsed["schema_version"].as_u64(),
            Some(LEDGER_SCHEMA_VERSION as u64)
        );
        assert_eq!(parsed["entries"][0]["source"], "official");
    });
}

// §6.2: a non-default origin source survives the round-trip
#[test]
fn custom_source_roundtrips() {
    with_state_dir(|_| {
        let mut e = entry("corp-db", "1.0.0");
        e.source = "corp".into();
        e.source_url = "https://registries.corp.internal".into();
        record_install(Path::new("/nonexistent-tmp"), e).unwrap();
        let state = load_state(Path::new("/nonexistent-tmp"));
        let got = state.get("corp-db").unwrap();
        assert_eq!(got.source, "corp");
        assert_eq!(got.source_url, "https://registries.corp.internal");
    });
}

#[test]
fn format_ts_is_utc_civil_time() {
    assert_eq!(format_ts(1_700_000_000), "2023-11-14 22:13:20");
    assert_eq!(format_ts(0), "1970-01-01 00:00:00");
}

// uninstall: traversal slug is rejected, nothing deleted
#[test]
fn uninstall_rejects_traversal_slug() {
    use vynkor_manager::dropin::uninstall;

    let tmp = tempdir().unwrap();
    let victim = tmp.path().join("victim");
    fs::create_dir_all(&victim).unwrap();

    temp_env::with_var(
        "VYNM_PLUGIN_DIR",
        Some(tmp.path().to_str().unwrap()),
        || {
            let err = uninstall("../../victim", Path::new("/nonexistent-tmp")).unwrap_err();
            assert!(err.to_string().contains("invalid slug"), "got: {err}");
            assert!(
                victim.exists(),
                "traversal must not delete outside plugin dir"
            );
        },
    );
}

// remove tolerates a missing dir when the state still tracks it (R10-02)
#[test]
fn uninstall_tolerates_missing_dir() {
    use vynkor_manager::dropin::uninstall;

    with_state_dir(|_| {
        let tmp = tempdir().unwrap();
        let plugin_dir = tmp.path().join("plugins");
        record_install(Path::new("/nonexistent-tmp"), entry("ping-pong", "0.1.0")).unwrap();
        temp_env::with_var(
            "VYNM_PLUGIN_DIR",
            Some(plugin_dir.to_str().unwrap()),
            || {
                uninstall("ping-pong", Path::new("/nonexistent-tmp")).unwrap();
                assert!(
                    load_state(Path::new("/nonexistent-tmp"))
                        .get("ping-pong")
                        .is_none(),
                    "state entry dropped"
                );
            },
        );
    });
}

// remove with neither state nor dir stays a hard error
#[test]
fn uninstall_unknown_plugin_errors() {
    use vynkor_manager::dropin::uninstall;

    with_state_dir(|_| {
        let tmp = tempdir().unwrap();
        let plugin_dir = tmp.path().join("plugins");
        temp_env::with_var(
            "VYNM_PLUGIN_DIR",
            Some(plugin_dir.to_str().unwrap()),
            || {
                let err = uninstall("ghost", Path::new("/nonexistent-tmp")).unwrap_err();
                assert!(
                    err.to_string().contains("not installed"),
                    "unexpected: {err}"
                );
            },
        );
    });
}

// remove deletes both the dir and the state entry
#[test]
fn uninstall_removes_dir_and_state() {
    use vynkor_manager::dropin::uninstall;

    with_state_dir(|_| {
        let tmp = tempdir().unwrap();
        let plugin_dir = tmp.path().join("plugins");
        let dest = plugin_dir.join("ping-pong");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("binary"), b"x").unwrap();
        record_install(Path::new("/nonexistent-tmp"), entry("ping-pong", "0.1.0")).unwrap();

        temp_env::with_var(
            "VYNM_PLUGIN_DIR",
            Some(plugin_dir.to_str().unwrap()),
            || {
                uninstall("ping-pong", Path::new("/nonexistent-tmp")).unwrap();
                assert!(!dest.exists(), "plugin dir removed");
                assert!(
                    load_state(Path::new("/nonexistent-tmp"))
                        .get("ping-pong")
                        .is_none(),
                    "state entry removed"
                );
            },
        );
    });
}
