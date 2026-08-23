use ed25519_dalek::SigningKey;

use super::{entry_from_fields, load_signing_key, sign_entry, verify_signature};
use crate::registry::signed_message;

fn sample_fields() -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    (
        "echo",
        "1.2.0",
        "abc123",
        "stable",
        "https://example.com/dist/echo-1.2.0.tar.gz",
        "0.1.0",
        "*",
    )
}

fn fixed_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

#[test]
fn roundtrip_sign_then_verify() {
    let key = fixed_key();
    let entry = entry_from_fields(
        sample_fields().0,
        sample_fields().1,
        sample_fields().2,
        sample_fields().3,
        sample_fields().4,
        sample_fields().5,
        sample_fields().6,
    );
    let sig = sign_entry(&key, &entry);
    assert_eq!(sig.len(), 128);
    verify_signature(&entry, &sig, &crate::keygen::public_key_hex(&key)).unwrap();
}

#[test]
fn deterministic_seed_produces_identical_signature_across_runs() {
    let (slug, version, sha256, status, url, min, max) = sample_fields();
    let a = sign_entry(
        &fixed_key(),
        &entry_from_fields(slug, version, sha256, status, url, min, max),
    );
    // fresh key object from the same seed — simulates a separate process run
    let b = sign_entry(
        &SigningKey::from_bytes(&[42u8; 32]),
        &entry_from_fields(slug, version, sha256, status, url, min, max),
    );
    assert_eq!(a, b);
    // and it signs the exact canonical message install-time checks use
    let msg = signed_message(&entry_from_fields(
        slug, version, sha256, status, url, min, max,
    ));
    assert_eq!(
        msg,
        "echo:1.2.0:abc123:stable:https://example.com/dist/echo-1.2.0.tar.gz:0.1.0:*"
    );
}

#[test]
fn tampered_field_fails_verify() {
    let key = fixed_key();
    let (slug, version, sha256, _status, url, min, max) = sample_fields();
    let signed_status = "beta";
    let sig = sign_entry(
        &key,
        &entry_from_fields(slug, version, sha256, signed_status, url, min, max),
    );
    // attacker flips status back to stable after signing
    let forged = entry_from_fields(slug, version, sha256, "stable", url, min, max);
    assert!(verify_signature(&forged, &sig, &crate::keygen::public_key_hex(&key)).is_err());
}

#[test]
fn wrong_public_key_fails_verify() {
    let key = fixed_key();
    let impostor = SigningKey::from_bytes(&[9u8; 32]);
    let (slug, version, sha256, status, url, min, max) = sample_fields();
    let entry = entry_from_fields(slug, version, sha256, status, url, min, max);
    let sig = sign_entry(&key, &entry);
    assert!(verify_signature(&entry, &sig, &crate::keygen::public_key_hex(&impostor)).is_err());
}

#[test]
fn load_signing_key_reads_bare_hex_seed_with_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("k.key");
    std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
    let key = load_signing_key(&path).unwrap();
    assert_eq!(
        crate::keygen::public_key_hex(&key),
        crate::keygen::public_key_hex(&SigningKey::from_bytes(&[0xabu8; 32]))
    );
}

#[test]
fn load_signing_key_rejects_short_seed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short.key");
    std::fs::write(&path, "aabb").unwrap();
    let err = load_signing_key(&path).unwrap_err();
    assert!(matches!(err, crate::error::VynmError::InvalidInput(m) if m.contains("64-hex-char")));
}
