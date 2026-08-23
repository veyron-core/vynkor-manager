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
