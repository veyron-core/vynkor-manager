//! vynm sign (V-14b): maintainer-side signing/verification of registry
//! entries. The message format lives ONLY in `registry::signed_message` —
//! this module constructs a `RegistryEntry` and defers to it, so the CLI can
//! never drift from what install-time verification expects.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};

use crate::error::VynmError;
use crate::registry::{hex_encode, verify_entry_signature, RegistryEntry};

/// Load the bare 64-hex-char seed (`VYN_SIGNING_KEY_HEX` convention).
/// Trailing whitespace tolerated; anything else is a hard input error.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, VynmError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| VynmError::InvalidInput(format!("read key file {}: {e}", path.display())))?;
    let seed_hex = text.trim();
    let bytes = crate::registry::hex_decode(seed_hex)?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        VynmError::InvalidInput(format!(
            "{}: expected a bare 64-hex-char ed25519 seed, got {} hex chars",
            path.display(),
            seed_hex.len()
        ))
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Assemble the entry whose canonical form will be signed. Only the seven
/// signed fields carry values; everything else stays empty — `signed_message`
/// reads exactly those seven.
#[allow(clippy::too_many_arguments)]
pub fn entry_from_fields(
    slug: &str,
    version: &str,
    sha256: &str,
    status: &str,
    archive_url: &str,
    min_kernel_version: &str,
    max_kernel_version: &str,
) -> RegistryEntry {
    RegistryEntry {
        id: String::new(),
        slug: slug.into(),
        name: String::new(),
        description: String::new(),
        version: version.into(),
        permissions: Vec::new(),
        archive_url: archive_url.into(),
        source_url: String::new(),
        sha256: sha256.into(),
        min_kernel_version: min_kernel_version.into(),
        max_kernel_version: max_kernel_version.into(),
        signature: String::new(),
        status: status.into(),
    }
}

/// 128 lowercase hex chars over the canonical S1 message.
pub fn sign_entry(key: &SigningKey, entry: &RegistryEntry) -> String {
    hex_encode(
        &key.sign(crate::registry::signed_message(entry).as_bytes())
            .to_bytes(),
    )
}

/// Verify-mode path: same gate install uses, fed the operator's public key.
pub fn verify_signature(
    entry: &RegistryEntry,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), VynmError> {
    let mut signed = entry.clone();
    signed.signature = signature_hex.trim().to_string();
    verify_entry_signature(&signed, public_key_hex)
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
