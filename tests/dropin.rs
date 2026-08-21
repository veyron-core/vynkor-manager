use std::fs;
use std::path::Path;

use tempfile::tempdir;
use vynkor_manager::dropin::{
    disable_plugin_config, enable_plugin_config, remove_plugin_config, write_plugin_config,
    DropinParams, Toggle,
};

fn params<'a>(slug: &'a str, binary: &'a str) -> DropinParams<'a> {
    DropinParams {
        slug,
        plugin_id: slug,
        binary_path: Path::new(binary),
        sandbox: true,
    }
}

// writes a per-plugin drop-in with binary path + id
#[test]
fn write_plugin_config_creates_dropin_file() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");

    assert!(write_plugin_config(
        &plugins_dir,
        &params(
            "ping-pong",
            "/home/u/.local/lib/veyron/plugins/ping-pong/ping-pong"
        )
    )
    .unwrap());

    let path = plugins_dir.join("ping-pong.yaml");
    assert!(path.exists());
    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("id: ping-pong"));
    assert!(content.contains("binary: /home/u/.local/lib/veyron/plugins/ping-pong/ping-pong"));
    assert!(content.contains("restart: on-failure"));
    assert!(content.contains("max_restarts: 5"));
    assert!(content.contains("sandbox: true"));
}

// sandbox comes from the caller's params (D3) — false renders false
#[test]
fn write_plugin_config_sandbox_false_renders() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");

    let mut p = params("network", "/x/network");
    p.sandbox = false;
    write_plugin_config(&plugins_dir, &p).unwrap();

    let content = fs::read_to_string(plugins_dir.join("network.yaml")).unwrap();
    assert!(content.contains("sandbox: false"));
}

// existing drop-in is left untouched (operator-tuned), and the write
// reports "not written"
#[test]
fn write_plugin_config_keeps_existing_file() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    fs::create_dir_all(&plugins_dir).unwrap();
    let path = plugins_dir.join("database.yaml");
    fs::write(&path, "id: database\nbinary: /custom/database\n").unwrap();

    assert!(!write_plugin_config(&plugins_dir, &params("database", "/x/database")).unwrap());

    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "id: database\nbinary: /custom/database\n"
    );
}

// a pre-planted symlink is never followed — the write reports "not written"
// and the symlink target stays untouched (M-09 class, O_EXCL boundary)
#[test]
fn write_plugin_config_does_not_follow_symlink() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    fs::create_dir_all(&plugins_dir).unwrap();
    let victim = tmp.path().join("victim.txt");
    fs::write(&victim, "do not touch").unwrap();
    std::os::unix::fs::symlink(&victim, plugins_dir.join("pwned.yaml")).unwrap();

    assert!(!write_plugin_config(&plugins_dir, &params("pwned", "/x/pwned")).unwrap());
    assert_eq!(fs::read_to_string(&victim).unwrap(), "do not touch");
}

// traversal slug is rejected, nothing written
#[test]
fn write_plugin_config_rejects_traversal_slug() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");

    assert!(write_plugin_config(&plugins_dir, &params("../evil", "/x/evil")).is_err());
    assert!(!tmp.path().join("evil.yaml").exists());
}

// creates the plugins.d dir when missing
#[test]
fn write_plugin_config_creates_plugins_dir() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("nested").join("plugins.d");

    write_plugin_config(&plugins_dir, &params("ai", "/x/ai")).unwrap();

    assert!(plugins_dir.join("ai.yaml").exists());
}

// removes the drop-in file, returns true
#[test]
fn remove_plugin_config_removes_file() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    write_plugin_config(&plugins_dir, &params("ping-pong", "/x/ping-pong-rs")).unwrap();

    let removed = remove_plugin_config(&plugins_dir, "ping-pong").unwrap();
    assert!(removed);
    assert!(!plugins_dir.join("ping-pong.yaml").exists());
}

// no drop-in for the slug → false, no error
#[test]
fn remove_plugin_config_missing_is_false() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");

    let removed = remove_plugin_config(&plugins_dir, "ghost").unwrap();
    assert!(!removed);
}

// removing the middle drop-in keeps sibling files
#[test]
fn remove_plugin_config_keeps_sibling_dropins() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");

    write_plugin_config(&plugins_dir, &params("ping-pong", "/x/ping-pong-rs")).unwrap();
    write_plugin_config(&plugins_dir, &params("network", "/x/network")).unwrap();
    write_plugin_config(&plugins_dir, &params("ai", "/x/ai")).unwrap();

    let removed = remove_plugin_config(&plugins_dir, "network").unwrap();
    assert!(removed);
    assert!(!plugins_dir.join("network.yaml").exists());
    assert!(plugins_dir.join("ping-pong.yaml").exists());
    assert!(plugins_dir.join("ai.yaml").exists());
}

// traversal slug is rejected, nothing deleted
#[test]
fn remove_plugin_config_rejects_traversal_slug() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    let victim = tmp.path().join("victim.yaml");
    fs::write(&victim, "keep").unwrap();

    let err = remove_plugin_config(&plugins_dir, "../victim").unwrap_err();
    assert!(err.to_string().contains("invalid slug"), "got: {err}");
    assert!(
        victim.exists(),
        "traversal must not delete outside plugins.d"
    );
}

// renames the active drop-in to <slug>.yaml.disabled
#[test]
fn disable_plugin_config_renames_active_dropin() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    write_plugin_config(&plugins_dir, &params("ping-pong", "/x/ping-pong-rs")).unwrap();
    let body = fs::read_to_string(plugins_dir.join("ping-pong.yaml")).unwrap();

    let outcome = disable_plugin_config(&plugins_dir, "ping-pong").unwrap();
    assert_eq!(outcome, Toggle::Toggled);
    assert!(!plugins_dir.join("ping-pong.yaml").exists());
    assert!(plugins_dir.join("ping-pong.yaml.disabled").exists());
    // the rename preserves the operator's tuning verbatim
    assert_eq!(
        fs::read_to_string(plugins_dir.join("ping-pong.yaml.disabled")).unwrap(),
        body
    );
}

// already disabled → Toggle::Already
#[test]
fn disable_plugin_config_already_disabled() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    fs::create_dir_all(&plugins_dir).unwrap();
    fs::write(plugins_dir.join("ai.yaml.disabled"), "id: ai\n").unwrap();

    let outcome = disable_plugin_config(&plugins_dir, "ai").unwrap();
    assert_eq!(outcome, Toggle::Already);
    assert!(plugins_dir.join("ai.yaml.disabled").exists());
}

// no drop-in at all → Toggle::Missing
#[test]
fn disable_plugin_config_missing() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");

    let outcome = disable_plugin_config(&plugins_dir, "ghost").unwrap();
    assert_eq!(outcome, Toggle::Missing);
}

// active + disabled both present → refuse (a rename would silently clobber)
#[test]
fn disable_plugin_config_refuses_when_both_exist() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    fs::create_dir_all(&plugins_dir).unwrap();
    fs::write(plugins_dir.join("ai.yaml"), "id: ai\n").unwrap();
    fs::write(plugins_dir.join("ai.yaml.disabled"), "id: ai\n").unwrap();

    let err = disable_plugin_config(&plugins_dir, "ai").unwrap_err();
    assert!(err.to_string().contains("remove one first"), "got: {err}");
    assert!(plugins_dir.join("ai.yaml").exists());
    assert!(plugins_dir.join("ai.yaml.disabled").exists());
}

// restores the drop-in from .yaml.disabled verbatim
#[test]
fn enable_plugin_config_restores_dropin() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    fs::create_dir_all(&plugins_dir).unwrap();
    let body = "id: ai\nbinary: /x/ai\n";
    fs::write(plugins_dir.join("ai.yaml.disabled"), body).unwrap();

    let outcome = enable_plugin_config(&plugins_dir, "ai").unwrap();
    assert_eq!(outcome, Toggle::Toggled);
    assert!(!plugins_dir.join("ai.yaml.disabled").exists());
    assert_eq!(
        fs::read_to_string(plugins_dir.join("ai.yaml")).unwrap(),
        body
    );
}

// already enabled → Toggle::Already
#[test]
fn enable_plugin_config_already_enabled() {
    let tmp = tempdir().unwrap();
    let plugins_dir = tmp.path().join("plugins.d");
    fs::create_dir_all(&plugins_dir).unwrap();
    fs::write(plugins_dir.join("ai.yaml"), "id: ai\n").unwrap();

    let outcome = enable_plugin_config(&plugins_dir, "ai").unwrap();
    assert_eq!(outcome, Toggle::Already);
    assert!(plugins_dir.join("ai.yaml").exists());
}
