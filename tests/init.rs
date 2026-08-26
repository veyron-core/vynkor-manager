//! First-run config materialization: `vynm init`, auto-seed on the default
//! product path, and the guarantee that explicit/legacy paths are never
//! touched. Every test spawns the real binary with an isolated `$HOME`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn isolated_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

fn vynm(home: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_vynm"))
        .env("HOME", home)
        .env_remove("VYN_CONFIG")
        .env_remove("VYNM_REGISTRY_URL")
        .env_remove("VYNM_MARKETPLACE_PUBLIC_KEY")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), format!("{stdout}{stderr}"))
}

fn product_config(home: &Path) -> PathBuf {
    home.join(".config/vyn/config.yaml")
}

// ── vynm init: writes once, then idempotent ──────────────────────────────────

#[test]
fn init_writes_commented_template_exactly_once() {
    let (_guard, home) = isolated_home();
    let cfg = product_config(&home);
    assert!(!cfg.exists());

    let (ok, out) = vynm(&home, &["init"]);
    assert!(ok, "{out}");
    assert!(cfg.is_file());
    let body = fs::read_to_string(&cfg).unwrap();
    assert!(body.contains("name: official"));
    assert!(body.contains("pub-6fd4e146631e43028372c95cbd2b9b42.r2.dev"));
    assert!(
        body.contains("public_key:"),
        "every field documented inline"
    );
    assert!(
        body.contains("# - name: corp"),
        "second-source example present as commented yaml"
    );

    // second run must NOT touch the file
    let before = fs::read_to_string(&cfg).unwrap();
    let (ok, out) = vynm(&home, &["init"]);
    assert!(ok, "{out}");
    assert!(out.contains("already exists"), "{out}");
    assert_eq!(before, fs::read_to_string(&cfg).unwrap());
}

#[test]
fn init_force_regenerates_a_trashed_config() {
    let (_guard, home) = isolated_home();
    let cfg = product_config(&home);
    vynm(&home, &["init"]);
    fs::write(&cfg, "# operator trashed this\nregistries: []\n").unwrap();

    let (ok, out) = vynm(&home, &["init", "--force"]);
    assert!(ok, "{out}");
    assert!(fs::read_to_string(&cfg).unwrap().contains("name: official"));
}

// ── auto-seed on first command through the DEFAULT path ─────────────────────

#[test]
fn first_command_seeds_the_default_product_path() {
    let (_guard, home) = isolated_home();
    let cfg = product_config(&home);
    assert!(!cfg.exists());

    let (ok, out) = vynm(&home, &["list"]);
    assert!(ok, "{out}");
    assert!(
        out.contains("created") && out.contains("config.yaml"),
        "expected a seed notice, got: {out}"
    );
    assert!(cfg.is_file(), "default path must materialize");
    assert!(fs::read_to_string(&cfg).unwrap().contains("name: official"));

    // a follow-up command parses the seeded file cleanly (no second notice)
    let (ok, out) = vynm(&home, &["list"]);
    assert!(ok, "{out}");
    assert!(!out.contains("created"), "{out}");
}

// ── explicit / env-pinned paths are NEVER seeded ────────────────────────────

#[test]
fn explicit_and_env_pinned_configs_are_left_alone() {
    let (_guard, home) = isolated_home();

    let custom = home.join("custom-config.yaml");
    let (ok, _out) = vynm(&home, &["--config", custom.to_str().unwrap(), "list"]);
    assert!(ok);
    assert!(
        !custom.exists(),
        "explicit --config must not be auto-seeded"
    );

    let pinned = home.join("vyn-config-env.yaml");
    let out = Command::new(env!("CARGO_BIN_EXE_vynm"))
        .env("HOME", &home)
        .env("VYN_CONFIG", &pinned)
        .args(["list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        !pinned.exists(),
        "$VYN_CONFIG paths must not be auto-seeded"
    );
}
