use crate::error::VynmError;

/// ma-17: one shape gate shared by slugs and plugin ids — non-empty ASCII
/// `[A-Za-z0-9._-]`, bounded length, never a bare path component. callers
/// layer their own extras (reserved names like `kernel`, tighter limits);
/// duplicating the charset here is how the two validators drifted apart.
/// ported verbatim from the kernel's `utils/validate.rs` (security boundary).
pub fn validate_identifier(id: &str, max_len: usize) -> Result<(), VynmError> {
    if id.is_empty() {
        return Err(VynmError::InvalidInput("must not be empty".into()));
    }
    if id.len() > max_len {
        return Err(VynmError::InvalidInput(format!(
            "too long ({} bytes, max {max_len})",
            id.len()
        )));
    }
    if id == "." || id == ".." {
        return Err(VynmError::InvalidInput(
            "'.' and '..' are reserved path components".into(),
        ));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(VynmError::InvalidInput(
            "only ASCII letters, digits, '.', '-', '_' are allowed".into(),
        ));
    }
    Ok(())
}
