use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::{generate_signing_key, public_key_hex, write_seed_file};
use crate::error::VynmError;

// tempdir must outlive the key file — returned alongside the path
fn tmp_key() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.key");
    (dir, path)
}

#[test]
fn generated_pubkey_is_64_lowercase_hex() {
    let key = generate_signing_key().unwrap();
    let hex = public_key_hex(&key);
    assert_eq!(hex.len(), 64);
    assert!(hex
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
}

#[test]
fn deterministic_seed_yields_matching_pubkey() {
    let seed = [7u8; 32];
    let a = ed25519_dalek::SigningKey::from_bytes(&seed);
    let b = ed25519_dalek::SigningKey::from_bytes(&seed);
    assert_eq!(public_key_hex(&a), public_key_hex(&b));
}

#[cfg(unix)]
#[test]
fn seed_file_created_with_0600() {
    let (_dir, path) = tmp_key();
    write_seed_file(&path, &[1u8; 32], false).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.len(), 64);
    assert_eq!(text, "0101".repeat(16));
}

#[cfg(unix)]
#[test]
fn forced_overwrite_keeps_0600() {
    let (_dir, path) = tmp_key();
    write_seed_file(&path, &[1u8; 32], false).unwrap();
    write_seed_file(&path, &[2u8; 32], true).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(fs::read_to_string(&path).unwrap(), "0202".repeat(16));
}

#[test]
fn refuses_overwrite_without_force() {
    let (_dir, path) = tmp_key();
    write_seed_file(&path, &[1u8; 32], false).unwrap();
    let err = write_seed_file(&path, &[2u8; 32], false).unwrap_err();
    assert!(matches!(err, VynmError::InvalidInput(m) if m.contains("--force")));
    assert_eq!(fs::read_to_string(&path).unwrap(), "0101".repeat(16));
}
