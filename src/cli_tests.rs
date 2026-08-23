use ed25519_dalek::SigningKey;

use super::{run, Cli, Command};
use crate::error::VynmError;

const SEED: [u8; 32] = [42; 32];

fn sign_cli(key: Option<&std::path::Path>, verify: bool) -> Cli {
    Cli {
        config: "config.yaml".into(),
        command: Command::Sign {
            key: key.map(|p| p.to_path_buf()),
            slug: "demo".into(),
            version: "1.0.0".into(),
            sha256: "abc123".into(),
            status: "stable".into(),
            archive_url: "https://example.com/demo.tar.gz".into(),
            min: "0.1.0".into(),
            max: "*".into(),
            verify,
            public_key: Some(crate::keygen::public_key_hex(&SigningKey::from_bytes(
                &SEED,
            ))),
            signature: None,
        },
    }
}

fn good_signature() -> String {
    let entry = crate::sign::entry_from_fields(
        "demo",
        "1.0.0",
        "abc123",
        "stable",
        "https://example.com/demo.tar.gz",
        "0.1.0",
        "*",
    );
    crate::sign::sign_entry(&SigningKey::from_bytes(&SEED), &entry)
}

fn set_signature(cli: &mut Cli, sig: Option<String>) {
    if let Command::Sign { signature, .. } = &mut cli.command {
        *signature = sig;
    }
}

#[tokio::test]
async fn verify_without_key_accepts_good_signature() {
    let mut cli = sign_cli(None, true);
    let sig = good_signature();
    set_signature(&mut cli, Some(sig));
    run(&cli).await.unwrap();
}

#[tokio::test]
async fn verify_without_key_rejects_tampered_with_exit_3() {
    let mut cli = sign_cli(None, true);
    let mut sig = good_signature();
    // flip one hex nibble
    let flipped = if sig.starts_with('a') { 'b' } else { 'a' };
    sig.replace_range(0..1, &flipped.to_string());
    set_signature(&mut cli, Some(sig));
    let err = run(&cli).await.unwrap_err();
    assert_eq!(super::exit_code(&err), super::EXIT_VERIFICATION);
}

#[tokio::test]
async fn sign_mode_still_requires_key() {
    let cli = sign_cli(None, false);
    let err = run(&cli).await.unwrap_err();
    assert!(
        matches!(err, VynmError::InvalidInput(ref m) if m.contains("--key")),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
async fn verify_with_key_still_works_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k.key");
    std::fs::write(&key_path, format!("{}\n", "2a".repeat(32))).unwrap();
    let mut cli = sign_cli(Some(&key_path), true);
    set_signature(&mut cli, Some(good_signature()));
    run(&cli).await.unwrap();
}

// ── V-09 resolution-engine internals ───────────────────────────────────────

use crate::source::{official_source, RegistrySource};

fn named(name: &str, enabled: bool) -> RegistrySource {
    RegistrySource {
        name: name.into(),
        enabled,
        ..official_source()
    }
}

#[test]
fn split_target_grammar() {
    assert_eq!(
        super::split_target("corp/database"),
        Some(("corp", "database"))
    );
    // bare slugs have no slash
    assert_eq!(super::split_target("database"), None);
    // degenerate forms fall back to bare-slug handling
    assert_eq!(super::split_target("/database"), None);
    assert_eq!(super::split_target("corp/"), None);
}

#[test]
fn bare_slug_candidates_origin_first_then_listed_order() {
    let sources = [named("a", true), named("b", true), named("c", true)];
    let out = super::bare_slug_candidates(&sources, Some("c"));
    let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["c", "a", "b"],
        "origin leads, listed order follows"
    );
}

#[test]
fn bare_slug_candidates_skips_disabled_and_unknown_origins() {
    let sources = [named("a", true), named("b", false), named("c", true)];
    let out = super::bare_slug_candidates(&sources, Some("b"));
    assert!(
        out.iter().all(|s| s.name != "b"),
        "disabled origin must not be probed"
    );

    let out = super::bare_slug_candidates(&sources, Some("gone"));
    let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["a", "c"], "unconfigured origin falls through");
}
