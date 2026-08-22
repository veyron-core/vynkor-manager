use std::collections::BTreeMap;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::VynmError;
use crate::source::RegistrySource;
use crate::state::{load_state, state_dir, InstalledState};

/// Bump whenever the on-disk cache layout changes incompatibly — a cache
/// written by an older tool must be read as empty, never misread.
///
/// v2 (S1): entries store the archive_url exactly as served (relative URLs
/// are resolved at install time, after signature verification, because the
/// signature binds the as-served URL). Same value as the kernel's cache —
/// the layout is identical, only the per-source path scheme (§6.3) is new.
pub const REGISTRY_CACHE_SCHEMA_VERSION: u32 = 2;

/// Default lifecycle status — the flat registry form predates `status`, so an
/// absent field must read as the benign value, not `""`.
fn default_status() -> String {
    "stable".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub archive_url: String,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub min_kernel_version: String,
    #[serde(default)]
    pub max_kernel_version: String,
    /// Ed25519 signature (hex, 64 bytes) over the full canonical entry
    /// `"{slug}:{version}:{sha256}:{status}:{archive_url}:{min_kernel_version}:
    /// {max_kernel_version}"` (see [`signed_message`]). Defaults empty for old
    /// cached/serialized entries — `verify_entry_signature` rejects an empty
    /// or malformed signature rather than treating it as "unsigned = trusted".
    #[serde(default)]
    pub signature: String,
    /// Lifecycle status: `stable` (default), `beta`, `deprecated`, `hidden`,
    /// `revoked`. Only `revoked` is enforced — install refuses it no matter
    /// how fresh the cache is (R10-03).
    #[serde(default = "default_status")]
    pub status: String,
}

impl RegistryEntry {
    /// `true` when the maintainer revoked this entry — never installable.
    pub fn is_revoked(&self) -> bool {
        self.status == "revoked"
    }
}

/// Registry document metadata (the v2 `meta` object): the authoritative
/// cache-invalidation signal, complementing the mtime TTL.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryMeta {
    #[serde(default, alias = "apiVersion")]
    pub api_version: Option<u32>,
    #[serde(default, alias = "lastUpdated")]
    pub last_updated: Option<String>,
}

/// Per-plugin bookkeeping persisted in the cache (R10-03) — the inputs for
/// offline upgrade detection (`installed vs registry` without a fetch).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachedPluginInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(default)]
    pub last_check: u64,
}

/// The on-disk registry cache (R10-03): a versioned wrapper around the
/// fetched registry document, one file per source (§6.3). The cache never
/// holds an entry install would refuse — revoked entries are kept (they are
/// refused *because* they are known), unsigned content is never cached at all.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryCache {
    pub schema_version: u32,
    #[serde(default)]
    pub last_check: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RegistryMeta>,
    #[serde(default)]
    pub entries: Vec<RegistryEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plugins: BTreeMap<String, CachedPluginInfo>,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, VynmError> {
    // % not is_multiple_of: stable only since 1.87, our MSRV is 1.85
    if s.len() % 2 != 0 {
        return Err(VynmError::Internal("invalid hex: odd length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| VynmError::Internal(format!("invalid hex: {e}")))
        })
        .collect()
}

/// The message a maintainer signature is computed over. Binding `slug` and
/// `version` (not just `sha256`) prevents splicing a valid signature onto a
/// different entry sharing the same archive hash; binding the full canonical
/// entry closes the S1 gaps (status flips, archive_url redirects, loosened
/// compat bounds all break it). Security boundary — ported verbatim.
fn signed_message(entry: &RegistryEntry) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        entry.slug,
        entry.version,
        entry.sha256,
        entry.status,
        entry.archive_url,
        entry.min_kernel_version,
        entry.max_kernel_version,
    )
}

/// Verify `entry.signature` against the source's configured public key.
/// Unlike the kernel original there is no pinned-key fallback: callers pass
/// `source.public_key` and simply don't reach this when it is `None`.
pub fn verify_entry_signature(
    entry: &RegistryEntry,
    public_key_hex: &str,
) -> Result<(), VynmError> {
    let key_bytes = hex_decode(public_key_hex)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| VynmError::Internal("marketplace public key must be 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| VynmError::Internal(format!("invalid marketplace public key: {e}")))?;

    let sig_bytes = hex_decode(&entry.signature).map_err(|_| {
        VynmError::Internal(format!(
            "Plugin '{}' has a malformed signature. Aborting — do not proceed.",
            entry.slug
        ))
    })?;
    let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        VynmError::Internal(format!(
            "Plugin '{}' signature must be 64 bytes. Aborting — do not proceed.",
            entry.slug
        ))
    })?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_strict(signed_message(entry).as_bytes(), &signature)
        .map_err(|_| {
            VynmError::Internal(format!(
                "Plugin '{}' failed signature verification — the maintainer signature does not \
                 match the entry (slug/version/sha256/status/archive_url/kernel-compat). \
                 Aborting — do not proceed.",
                entry.slug
            ))
        })
}

/// §6.3 — per-source cache path `<state_dir>/registry-cache/<stem>.json`,
/// where stem is the source name when filename-safe else a url hash. Active
/// from day one so multi-source later changes nothing about layout.
pub fn registry_cache_path(tmp_dir: &Path, source: &RegistrySource) -> PathBuf {
    let stem = if crate::validate::validate_identifier(&source.name, 64).is_ok() {
        source.name.clone()
    } else {
        url_hash(&source.url)
    };
    state_dir(tmp_dir)
        .join("registry-cache")
        .join(format!("{stem}.json"))
}

fn url_hash(url: &str) -> String {
    let digest = Sha256::digest(url.as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn cache_is_fresh(path: &Path, ttl: Duration) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|mtime| {
            SystemTime::now()
                .duration_since(mtime)
                .map(|age| age < ttl)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the cache file. A missing file, unparseable JSON, or a foreign
/// `schema_version` all read as empty — the next successful fetch rewrites it.
fn read_cache_file(path: &Path) -> Option<RegistryCache> {
    let data = fs::read_to_string(path).ok()?;
    match serde_json::from_str::<RegistryCache>(&data) {
        Ok(cache) if cache.schema_version == REGISTRY_CACHE_SCHEMA_VERSION => Some(cache),
        Ok(cache) => {
            tracing::warn!(
                "registry cache schema {} != supported {} — treating as empty",
                cache.schema_version,
                REGISTRY_CACHE_SCHEMA_VERSION
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                "corrupt registry cache at {}, ignoring: {e}",
                path.display()
            );
            None
        }
    }
}

/// Write the cache atomically (temp + rename in the same dir) so a crash
/// mid-write can never leave a half-written cache file.
fn write_cache_file(path: &Path, cache: &RegistryCache) -> Result<(), VynmError> {
    let parent = path
        .parent()
        .ok_or_else(|| VynmError::Cache("registry cache path has no parent dir".into()))?;
    fs::create_dir_all(parent).map_err(|e| VynmError::Cache(format!("create cache dir: {e}")))?;
    let tmp = parent.join(".registry-cache.json.tmp");
    let json = serde_json::to_string_pretty(cache)
        .map_err(|e| VynmError::Cache(format!("serialize registry cache: {e}")))?;
    fs::write(&tmp, json).map_err(|e| VynmError::Cache(format!("write cache: {e}")))?;
    fs::rename(&tmp, path).map_err(|e| VynmError::Cache(format!("write cache: {e}")))?;
    Ok(())
}

/// Fetch the raw registry document body, rejecting non-2xx and empty bodies
/// with actionable errors.
async fn fetch_from_network(url: &str) -> Result<String, VynmError> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| VynmError::Network(format!("fetch registry: {e}")))?;

    if !response.status().is_success() {
        return Err(VynmError::Network(format!(
            "registry fetch returned HTTP {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| VynmError::Network(format!("read registry response: {e}")))?;

    if body.trim().is_empty() {
        return Err(VynmError::Network(format!(
            "registry response body was empty (fetched from {url})"
        )));
    }

    Ok(body)
}

/// A parsed registry document — either the current flat array or the registry
/// v2 map form. v2's `versions` flatten into one [`RegistryEntry`] per
/// version; its root `revoked` list folds into each matching entry's status.
struct RegistryDocument {
    meta: Option<RegistryMeta>,
    entries: Vec<RegistryEntry>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RegistryDocShape {
    Flat(Vec<RegistryEntry>),
    Map(RegistryDocMap),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryDocMap {
    #[serde(default)]
    meta: Option<RegistryMeta>,
    #[serde(default)]
    revoked: Vec<String>,
    #[serde(flatten)]
    plugins: BTreeMap<String, MapPluginEntry>,
}

#[derive(Deserialize)]
struct MapPluginEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default, alias = "sourceUrl")]
    source_url: String,
    #[serde(default)]
    versions: BTreeMap<String, MapVersion>,
}

#[derive(Deserialize)]
struct MapVersion {
    #[serde(default, alias = "archiveUrl")]
    archive_url: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    signature: String,
    #[serde(default, alias = "minKernelVersion")]
    min_kernel_version: String,
    #[serde(default, alias = "maxKernelVersion")]
    max_kernel_version: String,
}

fn parse_registry_document(body: &str) -> Result<RegistryDocument, VynmError> {
    let shape: RegistryDocShape = serde_json::from_str(body)
        .map_err(|e| VynmError::Network(format!("parse registry JSON: {e}")))?;
    Ok(match shape {
        RegistryDocShape::Flat(entries) => RegistryDocument {
            meta: None,
            entries,
        },
        RegistryDocShape::Map(form) => {
            let mut entries = Vec::new();
            for (slug, plugin) in form.plugins {
                for (version, v) in plugin.versions {
                    let status = if form
                        .revoked
                        .iter()
                        .any(|r| r == &slug || r == &format!("{slug}@{version}"))
                    {
                        "revoked".into()
                    } else {
                        plugin.status.clone()
                    };
                    entries.push(RegistryEntry {
                        id: if plugin.id.is_empty() {
                            slug.clone()
                        } else {
                            plugin.id.clone()
                        },
                        slug: slug.clone(),
                        name: plugin.name.clone(),
                        description: plugin.description.clone(),
                        version,
                        permissions: plugin.permissions.clone(),
                        archive_url: v.archive_url,
                        source_url: plugin.source_url.clone(),
                        sha256: v.sha256,
                        min_kernel_version: v.min_kernel_version,
                        max_kernel_version: v.max_kernel_version,
                        signature: v.signature,
                        status,
                    });
                }
            }
            RegistryDocument {
                meta: form.meta,
                entries,
            }
        }
    })
}

/// Filter `entries` down to those whose maintainer signature verifies (T-11),
/// returning `(verified, dropped)` with the dropped slugs+reason for logging.
/// The cache never persists an entry install would refuse, so a stale-cache
/// fallback never serves unverified content.
fn verify_entries(
    entries: &[RegistryEntry],
    public_key_hex: &str,
) -> (Vec<RegistryEntry>, Vec<String>) {
    let mut verified = Vec::new();
    let mut dropped = Vec::new();
    for e in entries {
        match verify_entry_signature(e, public_key_hex) {
            Ok(()) => verified.push(e.clone()),
            Err(err) => dropped.push(format!("{}@{} ({err})", e.slug, e.version)),
        }
    }
    (verified, dropped)
}

/// Per-slug bookkeeping for the cache: the installed version (from the state
/// store) and the fetch time, so offline upgrade detection works without a
/// fetch.
fn snapshot_plugins(
    entries: &[RegistryEntry],
    installed: &InstalledState,
    at: u64,
) -> BTreeMap<String, CachedPluginInfo> {
    entries
        .iter()
        .map(|e| {
            (
                e.slug.clone(),
                CachedPluginInfo {
                    installed_version: installed.get(&e.slug).map(|i| i.version.clone()),
                    last_check: at,
                },
            )
        })
        .collect()
}

/// D8 transport gate shared by the registry URL (here) and archive URLs
/// (`ensure_archive_url_allowed`, called by the V-05 installer): plain http://
/// is refused unless this source explicitly opted in via `allow_unsigned`.
fn require_https_or_consent(
    what: &str,
    url: &str,
    source: &RegistrySource,
) -> Result<(), VynmError> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") && source.allow_unsigned {
        tracing::warn!(
            "registry '{}': {} uses insecure http:// — allowed by allow_unsigned on this source",
            source.name,
            what
        );
        return Ok(());
    }
    Err(VynmError::Internal(format!(
        "refusing insecure http:// {what} on registry '{}' — set allow_unsigned: true \
         on this source to accept unencrypted transports",
        source.name
    )))
}

/// D8: refuse an http:// archive URL unless the source allows it. The V-05
/// installer calls this after signature verification, before any download.
pub fn ensure_archive_url_allowed(
    archive_url: &str,
    source: &RegistrySource,
) -> Result<(), VynmError> {
    require_https_or_consent("archive_url", archive_url, source)
}

/// §7.3 decision matrix — pure so tests can pin every branch:
/// - key present → verify signatures (unchanged behavior)
/// - no key + interactive TTY → ask the operator (`Prompt`)
/// - no key + non-TTY + `allow_unsigned` → proceed with a loud warning
/// - no key + non-TTY + no flag → hard error naming the exact knob
#[derive(Debug, PartialEq, Eq)]
pub enum UnsignedAction {
    VerifySignatures,
    PromptOperator,
    ProceedWithWarning,
    HardError,
}

pub(crate) fn unsigned_action(
    key_present: bool,
    interactive: bool,
    allow_unsigned: bool,
) -> UnsignedAction {
    if key_present {
        UnsignedAction::VerifySignatures
    } else if interactive {
        UnsignedAction::PromptOperator
    } else if allow_unsigned {
        UnsignedAction::ProceedWithWarning
    } else {
        UnsignedAction::HardError
    }
}

/// What fetch may do with the document after the consent gate.
#[derive(Debug)]
enum Consent {
    /// entries verify against the source key; verified ones get cached
    Verify,
    /// operator-consented unsigned content: served live, never cached
    Unverified,
}

/// Runtime half of the §7.3 gate: turns the matrix decision into either a
/// consent outcome or an error. `interactive` is injected for tests; prod
/// passes stdin's TTY status.
fn enforce_unsigned_consent(
    source: &RegistrySource,
    interactive: bool,
) -> Result<Consent, VynmError> {
    match unsigned_action(
        source.public_key.is_some(),
        interactive,
        source.allow_unsigned,
    ) {
        UnsignedAction::VerifySignatures => Ok(Consent::Verify),
        UnsignedAction::ProceedWithWarning => {
            tracing::warn!(
                "registry '{}': no marketplace_public_key configured — content is NOT \
                 signature-verified (allowed by allow_unsigned)",
                source.name
            );
            Ok(Consent::Unverified)
        }
        UnsignedAction::HardError => Err(VynmError::Internal(format!(
            "registry '{}' has no marketplace_public_key configured and content would be \
             accepted without signature verification — set allow_unsigned: true on this \
             source to consent explicitly (non-interactive run)",
            source.name
        ))),
        UnsignedAction::PromptOperator => {
            eprintln!(
                "⚠ registry '{}': no marketplace_public_key configured — content will NOT be \
                 signature-verified.",
                source.name
            );
            eprintln!("download anyway? [y/N] ");
            let mut line = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(_) if line.trim().eq_ignore_ascii_case("y") => Ok(Consent::Unverified),
                _ => Err(VynmError::Internal(format!(
                    "registry '{}': unsigned download refused by operator",
                    source.name
                ))),
            }
        }
    }
}

/// Fetch the registry for `source`, using the per-source disk cache when fresh
/// (§6.3). `refresh = true` bypasses the TTL. On network failure falls back to
/// the last *verified* stale cache with a warning; errors only when the
/// network fails and no usable cache exists.
pub async fn fetch_registry(
    source: &RegistrySource,
    refresh: bool,
    tmp_dir: &Path,
) -> Result<Vec<RegistryEntry>, VynmError> {
    let path = registry_cache_path(tmp_dir, source);
    let installed = load_state(tmp_dir);
    fetch_registry_from(source, refresh, &path, &installed).await
}

/// Internal implementation — separated so tests can inject a cache path and an
/// installed-state snapshot.
pub(crate) async fn fetch_registry_from(
    source: &RegistrySource,
    refresh: bool,
    path: &Path,
    installed: &InstalledState,
) -> Result<Vec<RegistryEntry>, VynmError> {
    require_https_or_consent("registry url", &source.url, source)?;

    let ttl = Duration::from_secs(source.cache_ttl_secs);

    if !refresh && cache_is_fresh(path, ttl) {
        if let Some(cache) = read_cache_file(path) {
            if !cache.entries.is_empty() {
                return Ok(cache.entries);
            }
        }
    }

    match fetch_from_network(&source.url).await {
        Ok(body) => {
            // Entries stay as served — relative archive_urls resolve at
            // install time, after signature verification (S1).
            let doc = parse_registry_document(&body)?;
            match enforce_unsigned_consent(source, std::io::stdin().is_terminal())? {
                Consent::Verify => {
                    let key = source.public_key.as_deref().expect("consent implies key");
                    let (verified, dropped) = verify_entries(&doc.entries, key);
                    if !dropped.is_empty() {
                        if verified.is_empty() {
                            // Never clobber a good snapshot with an
                            // all-unverified fetch (compromised channel /
                            // wrong key): keep the previous cache. The
                            // fetched entries still go to the caller —
                            // install re-verifies per entry and fails closed.
                            tracing::warn!(
                                "registry '{}': 0/{} entries verified — keeping previous cache: {:?}",
                                source.name,
                                doc.entries.len(),
                                dropped
                            );
                        } else {
                            tracing::warn!(
                                "registry '{}': dropped {} unverified entries from cache: {:?}",
                                source.name,
                                dropped.len(),
                                dropped
                            );
                        }
                    }

                    if !verified.is_empty() {
                        let cache = RegistryCache {
                            schema_version: REGISTRY_CACHE_SCHEMA_VERSION,
                            last_check: now_secs(),
                            meta: doc.meta,
                            plugins: snapshot_plugins(&verified, installed, now_secs()),
                            entries: verified,
                        };
                        if let Err(e) = write_cache_file(path, &cache) {
                            tracing::warn!("failed to write registry cache: {e}");
                        }
                    }
                    Ok(doc.entries)
                }
                Consent::Unverified => {
                    // unsigned content is served live and never cached — the
                    // cache invariant ("only verified entries") stays intact.
                    Ok(doc.entries)
                }
            }
        }
        Err(network_err) => {
            if let Some(cache) = read_cache_file(path) {
                if !cache.entries.is_empty() {
                    tracing::warn!(
                        "registry '{}' fetch failed ({}); using stale verified cache",
                        source.name,
                        network_err
                    );
                    return Ok(cache.entries);
                }
            }
            Err(network_err)
        }
    }
}

/// Resolve relative `archive_url` values against the registry's own base URL.
/// Registry v2 entries may use relative URLs so the artifact store can move
/// hosts with a one-line config change. Resolution happens only at install
/// time, after `verify_entry_signature` — the signature binds the URL exactly
/// as served (S1). Ported verbatim.
pub fn resolve_relative_archive_urls(entries: &mut [RegistryEntry], base_url: &str) {
    let Ok(base) = url::Url::parse(base_url) else {
        tracing::warn!(
            "registry: cannot resolve relative archive_urls against non-URL base {base_url:?}"
        );
        return;
    };
    for entry in entries {
        // Url::parse fails for relative references — that error IS the signal.
        if url::Url::parse(&entry.archive_url).is_err() {
            if let Ok(resolved) = base.join(&entry.archive_url) {
                entry.archive_url = resolved.to_string();
            }
        }
    }
}

/// C2: shell-completion slug listing, moved here wholesale from the kernel's
/// `cli/complete.rs`. CLI wiring lands in V-06.
pub async fn complete_slugs(source: &RegistrySource, tmp_dir: &Path) -> Result<(), VynmError> {
    let entries = fetch_registry(source, false, tmp_dir).await?;
    for e in entries {
        println!("{}", e.slug);
    }
    Ok(())
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
