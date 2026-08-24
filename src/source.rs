//! §6.1 registry sources: one configured origin of plugin registries.
//!
//! V-04 constructs exactly one instance from today's single-source config
//! keys (`registry_url` / `marketplace_public_key` / `registry_cache_ttl_secs`
//! → [`official_source`] when unset); multi-source parsing is V-09. Every
//! fetch/verify function takes `&RegistrySource` instead of loose tuples, so
//! adding N sources later changes resolution logic, not signatures.

/// The built-in default source entry (D5): the pinned maintainer key and the
/// official registry URL live HERE and nowhere else — no other compiled-in
/// URL or key may exist in this crate (CI/test-enforced). An operator config
/// overrides any field by constructing a different source.
pub fn official_source() -> RegistrySource {
    RegistrySource {
        name: "official".into(),
        // cloudflare r2 mirror while the custom domain is pending; swap to
        // https://plugins.<domain>/registry.json once connected
        url: "https://pub-6fd4e146631e43028372c95cbd2b9b42.r2.dev/registry.json".into(),
        public_key: Some(
            // offline maintainer key; rotate = re-sign entries + ship a new
            // default here. Private half never touches any repo.
            "6ee352d706eaf5b5114a1252fb76bb8a2bfbf177b0e4c8e9c21f73b9019083ee".into(),
        ),
        allow_unsigned: false,
        cache_ttl_secs: 3600,
        enabled: true,
    }
}

/// §6.1 — a named registry origin. `public_key: None` means "no signature
/// verification"; such a source must be explicitly opted in via
/// `allow_unsigned` when non-interactive (§7.3 gating).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySource {
    /// Ledger/cache identity (`installed.json#source`, cache file name).
    pub name: String,
    pub url: String,
    pub public_key: Option<String>,
    /// D8/§7.3 consent knob: accept http:// URLs and unsigned content from
    /// this source in non-interactive runs.
    pub allow_unsigned: bool,
    pub cache_ttl_secs: u64,
    pub enabled: bool,
}

impl Default for RegistrySource {
    fn default() -> Self {
        official_source()
    }
}
