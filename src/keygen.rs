//! vynm keygen (V-14a): ed25519 signing keys for registry publishers.
//! Key format is the historical `VEYRON_SIGNING_KEY_HEX` convention —
//! a bare 64-hex-char seed, nothing else on disk or stdout.

use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::VynmError;
use crate::registry::hex_encode;

pub const SEED_LEN: usize = 32;

/// os-rng seed → signing key. getrandom failure is an Internal, not Io:
/// it is never a file problem.
pub fn generate_signing_key() -> Result<SigningKey, VynmError> {
    let mut seed = [0u8; SEED_LEN];
    getrandom::getrandom(&mut seed)
        .map_err(|e| VynmError::Internal(format!("os rng failed: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn public_key_hex(key: &SigningKey) -> String {
    let verifying: VerifyingKey = key.into();
    hex_encode(&verifying.to_bytes())
}

/// Write the seed as 64 lowercase hex chars. Refuses to clobber without
/// `force`. On unix the file is created 0600 from the first open (O_EXCL +
/// mode), so the secret is never briefly world-readable; `force` removes
/// then recreates rather than truncating in place.
pub fn write_seed_file(path: &Path, seed: &[u8; SEED_LEN], force: bool) -> Result<(), VynmError> {
    if path.exists() {
        if !force {
            return Err(VynmError::InvalidInput(format!(
                "{} already exists — pass --force to overwrite",
                path.display()
            )));
        }
        std::fs::remove_file(path)?;
    }
    let text = hex_encode(seed);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .mode(0o600)
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
#[path = "keygen_tests.rs"]
mod tests;
