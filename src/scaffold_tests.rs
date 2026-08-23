use std::fs;
use std::path::PathBuf;

use super::scaffold;
use crate::error::VynmError;

fn tmp_base() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn scaffold_creates_all_files_with_name_substituted() {
    let dir = tmp_base();
    scaffold(dir.path(), "weather-bot", false).unwrap();
    let root = dir.path().join("weather-bot");
    for rel in [
        "plugin.json",
        "Cargo.toml",
        "src/main.rs",
        ".gitignore",
        "README.md",
    ] {
        assert!(root.join(rel).exists(), "missing {rel}");
    }
    let manifest = fs::read_to_string(root.join("plugin.json")).unwrap();
    assert!(manifest.contains("\"plugin_id\": \"weather-bot\""));
    assert!(manifest.contains("\"binary\": \"weather-bot\""));
    let cargo = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("name = \"weather-bot\""));
    assert!(cargo.contains("vynkor-sdk = \"0.0.3\""));
    let main = fs::read_to_string(root.join("src/main.rs")).unwrap();
    assert!(main.contains("\"weather-bot\""));
    assert!(main.contains("hello from weather-bot"));
    // no placeholder survives anywhere
    for rel in ["plugin.json", "Cargo.toml", "src/main.rs", "README.md"] {
        let text = fs::read_to_string(root.join(rel)).unwrap();
        assert!(!text.contains("{{name}}"), "{{name}} left in {rel}");
    }
}

#[test]
fn invalid_name_rejected() {
    let dir = tmp_base();
    let err = scaffold(dir.path(), "../evil", false).unwrap_err();
    assert!(matches!(err, VynmError::InvalidInput(_)));
    assert!(!dir.path().join("../evil").exists());
}

#[test]
fn refuses_existing_dir_without_force() {
    let dir = tmp_base();
    scaffold(dir.path(), "demo", false).unwrap();
    let err = scaffold(dir.path(), "demo", false).unwrap_err();
    assert!(matches!(err, VynmError::InvalidInput(m) if m.contains("--force")));
}

#[test]
fn force_overwrites_existing_files() {
    let dir = tmp_base();
    scaffold(dir.path(), "demo", false).unwrap();
    let root: PathBuf = dir.path().join("demo");
    fs::write(root.join("README.md"), "stale").unwrap();
    scaffold(dir.path(), "demo", true).unwrap();
    assert!(fs::read_to_string(root.join("README.md"))
        .unwrap()
        .contains("# demo"));
}

/// Full acceptance: the scaffold must compile against the published
/// vynkor-sdk 0.0.3. Needs crates.io network access.
#[test]
#[ignore = "requires crates.io network access — run locally with `cargo test -- --ignored`"]
fn scaffolded_plugin_compiles_against_published_sdk() {
    let dir = tmp_base();
    scaffold(dir.path(), "compile-check", false).unwrap();
    let root = dir.path().join("compile-check");
    let status = std::process::Command::new("cargo")
        .args(["build"])
        .current_dir(&root)
        .status()
        .expect("spawn cargo");
    assert!(status.success(), "scaffolded plugin failed to build");
}
