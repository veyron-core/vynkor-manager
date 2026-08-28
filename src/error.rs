use std::io;

/// Manager-side error type. Variant set mirrors the kernel's `VynkorError`
/// slice that the ported code needs, so ports stay mechanical and message
/// texts survive verbatim.
#[derive(Debug, thiserror::Error)]
pub enum VynmError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("cache error: {0}")]
    Cache(String),
    /// Security-refusal class (signature/digest/revocation/zip-slip/tampering):
    /// `cli::exit_code` maps this variant to 3 by type — never reintroduce
    /// message-sniffing for exit codes.
    #[error("{0}")]
    Verification(String),
    #[error("plugin not found: {0}")]
    PluginNotFound(String),
    #[error("network error: {0}")]
    Network(String),
}
