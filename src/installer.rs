use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use indicatif::{ProgressBar, ProgressStyle};
use semver::Version;
use sha2::{Digest, Sha256};

use crate::dropin::plugin_dir;
use crate::error::VynmError;
use crate::registry::{
    ensure_archive_url_allowed, resolve_relative_archive_urls, verify_entry_signature,
    RegistryEntry,
};
use crate::source::RegistrySource;
use crate::state::{load_state, record_install, InstalledEntry};
use vynkor_wire::manifest::{validate_manifest, InstallManifest};

/// What `install` placed on disk, so the caller can write a per-plugin
/// drop-in auto-spawn config (V-06 composes it with [`DropinParams`](crate::dropin::DropinParams)).
#[derive(Debug)]
pub struct InstalledPlugin {
    pub slug: String,
    pub plugin_id: String,
    pub version: String,
    /// Absolute path of the installed executable (dest / manifest.binary).
    pub binary_path: PathBuf,
    /// D3: the plugin's own sandbox hint (`plugin.json`, default true) —
    /// replaces the old hardcoded plugin-id special case.
    pub sandbox_hint: bool,
}

/// Staging directory for an in-progress install. Deliberately placed inside
/// `plugin_dir()` rather than `/tmp` — the final install step atomically
/// renames this directory into place, and `fs::rename` fails with EXDEV when
/// source and destination are on different filesystems, which `/tmp`
/// (often tmpfs) commonly is relative to the plugin directory.
fn tmp_install_dir(base: &Path, slug: &str) -> PathBuf {
    base.join(format!(".install-tmp-{slug}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_file(path: &Path) -> Result<String, VynmError> {
    let bytes = fs::read(path)?;
    Ok(hex_encode(&Sha256::digest(&bytes)))
}

/// Recursively gather (relpath, full path, is_dir); forward-slash relpaths,
/// symlinks skipped entirely — extract_zip never creates them, so the digest
/// must never see one either.
fn collect_tree(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(String, PathBuf, bool)>,
) -> Result<(), VynmError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if ft.is_dir() {
            out.push((rel.clone(), entry.path(), true));
            collect_tree(&entry.path(), &rel, out)?;
        } else {
            out.push((rel, entry.path(), false));
        }
    }
    Ok(())
}

/// V-13 canonical digest of an installed tree. Entries sorted by relpath;
/// each file feeds `<relpath>\n<mode:o>\n<len>\n<sha256(file)>\n` with
/// `mode & 0o7777` (exec-bit changes are tampering), each dir feeds
/// `<relpath>/\n`. Computed once at install and re-checked by `vynm verify`.
pub fn tree_digest(dir: &Path) -> Result<String, VynmError> {
    let mut items: Vec<(String, PathBuf, bool)> = Vec::new();
    collect_tree(dir, "", &mut items)?;
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (rel, full, is_dir) in items {
        if is_dir {
            hasher.update(format!("{rel}/\n"));
            continue;
        }
        let meta = fs::metadata(&full)?;
        let mode = meta.permissions().mode() & 0o7777;
        let file_hash = sha256_file(&full)?;
        hasher.update(format!("{rel}\n{mode:o}\n{}\n{file_hash}\n", meta.len()));
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// D2 pre-flight: ask the local kernel for its version so manifest compat can
/// be checked advisory-style. The kernel is the compat AUTHORITY — vynm never
/// guesses from its own package version and never fails the install here.
/// Returns the kernel version when reachable, else None (range check skipped;
/// boot-time validation owns it). `$VYNM_KERNEL_URL` overrides the endpoint,
/// which is the kernel's `/health` route.
async fn preflight_kernel_version(entry: &RegistryEntry) -> Option<Version> {
    let base = std::env::var("VYNM_KERNEL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let url = format!("{base}/health");
    let body = match reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp.text().await.ok()?,
        _ => {
            tracing::warn!(
                "kernel not reachable at {url} — skipping install-time compat check \
                 (compat enforced at kernel boot)"
            );
            return None;
        }
    };
    let version = serde_json::from_str::<serde_json::Value>(&body)
        .ok()?
        .get("version")?
        .as_str()?
        .to_string();
    let kernel_ver = match Version::parse(&version) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("kernel reported unparsable version '{version}': {e}");
            return None;
        }
    };
    // advisory only — a mismatch warns, never blocks (D2)
    if let Err(e) = vynkor_wire::manifest::check_kernel_compatibility(
        &entry.slug,
        &entry.min_kernel_version,
        &entry.max_kernel_version,
        &kernel_ver,
    ) {
        tracing::warn!("{e}. Upgrade Veyron before restarting the kernel.");
    }
    Some(kernel_ver)
}

/// Execute the atomic installation pipeline for a plugin entry:
/// resolve → revoke-gate → signature → download → digest → extract →
/// validate (staged copy) → permission-confirm gate (V-10) → swap → record.
/// Drop-in writing stays with the caller (V-06).
///
/// V-10: `confirm` is the operator's consent gate, invoked with the parsed
/// manifest of the STAGED copy before anything user-visible happens (dest
/// swap, ledger record; drop-in is caller-side). An Err from the gate aborts
/// exactly like a failed final validation: staging removed, dest/bak
/// untouched, nothing recorded.
#[allow(clippy::too_many_arguments)]
pub async fn install(
    entries: &[RegistryEntry],
    target: &str,
    source: &RegistrySource,
    tmp_dir: &Path,
    max_archive_bytes: u64,
    max_extracted_bytes: u64,
    max_archive_entries: usize,
    confirm: impl FnOnce(&InstallManifest) -> Result<(), VynmError>,
) -> Result<InstalledPlugin, VynmError> {
    // Step 1 — Resolve metadata
    let entry = entries
        .iter()
        .find(|e| e.slug == target || e.id == target)
        .ok_or_else(|| {
            VynmError::Internal(format!(
                "Plugin '{target}' not found. Run 'vynm search <query>' to browse."
            ))
        })?;

    // R10-03 — a revoked entry is never installable, whether it came from a
    // fresh fetch or the stale cache: revocation outlives the cache TTL.
    if entry.is_revoked() {
        return Err(VynmError::Verification(format!(
            "Plugin '{}' v{} is revoked by the maintainer. Aborting — do not install.",
            entry.slug, entry.version
        )));
    }

    // Step 2 — D2: no hard install-time compat gate. Advisory pre-flight only;
    // the kernel re-validates authoritatively at boot.
    let kernel_ver = preflight_kernel_version(entry).await;

    let plugin_base = plugin_dir(tmp_dir);

    // R10-02 — same version already installed (state + dir present): warn and
    // skip the whole pipeline instead of re-downloading/re-extracting.
    let dest = plugin_base.join(&entry.slug);
    if let Some(already) = skip_reinstall(tmp_dir, &entry.slug, &entry.version, &dest) {
        println!(
            "✓ '{slug}' v{version} is already installed at {dest}/ — nothing to re-install.",
            slug = entry.slug,
            version = entry.version,
            dest = dest.display(),
        );
        return Ok(already);
    }

    let stage_dir = tmp_install_dir(&plugin_base, &entry.slug);
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir).map_err(VynmError::Io)?;

    // Step 3 — Maintainer signature check (T-11/S1): runs before the download
    // so a forged archive_url can never trigger a request (request forgery),
    // and binds slug/version/sha256/status/archive_url/min/max. A consented
    // unsigned source (§7.3) has nothing to verify against — the sha256
    // digest below remains mandatory integrity enforcement either way.
    if let Some(key) = source.public_key.as_deref() {
        if let Err(e) = verify_entry_signature(entry, key) {
            let _ = fs::remove_dir_all(&stage_dir);
            return Err(e);
        }
    } else {
        tracing::warn!(
            "registry '{}': installing '{}' without signature verification (unsigned source)",
            source.name,
            entry.slug
        );
    }

    // The signature binds the archive_url as served — a relative URL (registry
    // v2) is resolved against the registry base only now, after verification.
    let mut entry = entry.clone();
    resolve_relative_archive_urls(std::slice::from_mut(&mut entry), &source.url);

    // D8 — https-only unless this source opted out; refuse before any bytes move.
    ensure_archive_url_allowed(&entry.archive_url, source)?;

    // Step 4 — Download to staging dir
    let bytes =
        match download_with_progress(&entry.archive_url, &entry.slug, max_archive_bytes).await {
            Ok(b) => b,
            Err(e) => {
                let _ = fs::remove_dir_all(&stage_dir);
                return Err(e);
            }
        };

    let archive_path = stage_dir.join(format!("{}.zip", entry.slug));
    if let Err(e) = fs::write(&archive_path, &bytes) {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(VynmError::Io(e));
    }

    // Step 5 — SHA-256 integrity check (mandatory even for unsigned sources)
    let actual_hash = hex_encode(&Sha256::digest(&bytes));
    if actual_hash != entry.sha256 {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(VynmError::Verification(format!(
            "Archive integrity check failed. Expected {}, got {}. Aborting — do not proceed.",
            entry.sha256, actual_hash
        )));
    }

    // Steps 6–9 — extract → validate → gate → digest → swap → record (shared
    // with the V-15 archive pipeline; identical security boundaries).
    commit_staged(
        tmp_dir,
        &stage_dir,
        &entry.slug,
        kernel_ver.as_ref(),
        actual_hash,
        &source.name,
        &source.url,
        max_extracted_bytes,
        max_archive_entries,
        confirm,
    )
}

/// Shared tail of both install pipelines (registry V-05, local-archive V-15):
/// the archive bytes are already written to `<stage_dir>/<slug>.zip` and their
/// sha256 computed. Extracts (zip-slip guarded), validates the manifest on the
/// STAGED copy, runs the V-10 permission gate, digests the tree (V-13),
/// atomically swaps into the plugin dir (bak/rename) and records the ledger.
/// Every failure below the extract removes staging and leaves dest untouched.
#[allow(clippy::too_many_arguments)]
fn commit_staged(
    tmp_dir: &Path,
    stage_dir: &Path,
    slug: &str,
    kernel_ver: Option<&Version>,
    actual_hash: String,
    source_name: &str,
    source_url: &str,
    max_extracted_bytes: u64,
    max_archive_entries: usize,
    confirm: impl FnOnce(&InstallManifest) -> Result<(), VynmError>,
) -> Result<InstalledPlugin, VynmError> {
    let plugin_base = plugin_dir(tmp_dir);
    let dest = plugin_base.join(slug);
    let archive_path = stage_dir.join(format!("{slug}.zip"));

    // Step 6 — Extract to temporary folder (zip-slip protection)
    let extract_dir = stage_dir.join("extracted");
    if let Err(e) = fs::create_dir_all(&extract_dir) {
        let _ = fs::remove_dir_all(stage_dir);
        return Err(VynmError::Io(e));
    }

    // Manifest v2 `files` extraction allowlist, read from the archive's
    // plugin.json IN MEMORY before extraction. `None` (no plugin.json, no
    // `files` key, or unreadable) = legacy extract-everything.
    let allowlist = read_files_allowlist(&archive_path);

    if let Err(e) = extract_zip(
        &archive_path,
        &extract_dir,
        max_extracted_bytes,
        max_archive_entries,
        allowlist.as_ref(),
    ) {
        let _ = fs::remove_dir_all(stage_dir);
        return Err(e);
    }

    // Step 7 — Final validation of plugin.json, now BEFORE the swap (V-10
    // reorder): the preview must come from the real parsed manifest, and a
    // bad manifest then never touches dest at all. Kernel version comes from
    // the pre-flight probe (Some → range checked; None → skipped per D2);
    // the permission policy is the wire default_resolver.
    let manifest = match validate_manifest(
        &extract_dir.join("plugin.json"),
        kernel_ver,
        vynkor_wire::manifest::default_resolver,
    ) {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_dir_all(stage_dir);
            return Err(VynmError::Internal(e.to_string()));
        }
    };

    // Step 8 — V-10 confirmation gate: everything below this line is
    // user-visible (dest swap, ledger record; drop-in is caller-side), so the
    // operator's consent lands here, after validation but before any rename.
    if let Err(e) = confirm(&manifest) {
        let _ = fs::remove_dir_all(stage_dir);
        return Err(e);
    }

    // V-13 — tree digest over the staged copy BEFORE the swap: the bytes
    // renamed into dest are exactly what gets recorded.
    let tree_sha256 = match tree_digest(&extract_dir) {
        Ok(h) => Some(h),
        Err(e) => {
            let _ = fs::remove_dir_all(stage_dir);
            return Err(e);
        }
    };

    // Step 9 — Atomic move to plugin directory (post-gate failures still roll back)
    if let Err(e) = fs::create_dir_all(&plugin_base) {
        let _ = fs::remove_dir_all(stage_dir);
        return Err(VynmError::Io(e));
    }

    let bak = plugin_base.join(format!("{slug}.bak"));
    let had_existing = dest.exists();

    if had_existing {
        if bak.exists() {
            let _ = fs::remove_dir_all(&bak);
        }
        if let Err(e) = fs::rename(&dest, &bak) {
            let _ = fs::remove_dir_all(stage_dir);
            return Err(VynmError::Io(e));
        }
    }

    if let Err(e) = fs::rename(&extract_dir, &dest) {
        if had_existing {
            let _ = fs::rename(&bak, &dest);
        }
        let _ = fs::remove_dir_all(stage_dir);
        return Err(VynmError::Io(e));
    }

    if had_existing {
        let _ = fs::remove_dir_all(&bak);
    }
    let _ = fs::remove_dir_all(stage_dir);

    // R10-02 — record in the explicit state store; a plugin on disk but
    // untracked is exactly the drift this store exists to prevent. §6.2: the
    // origin source name rides along for future update resolution. V-15:
    // archive installs record `source: "local"` with the raw path-or-URL.
    record_install(
        tmp_dir,
        InstalledEntry {
            slug: slug.to_string(),
            version: manifest.version.clone(),
            sha256: actual_hash,
            installed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            source_url: source_url.to_string(),
            source: source_name.to_string(),
            tree_sha256,
        },
    )?;

    Ok(InstalledPlugin {
        slug: slug.to_string(),
        plugin_id: manifest.plugin_id.clone(),
        version: manifest.version.clone(),
        binary_path: dest.join(&manifest.binary),
        sandbox_hint: manifest.sandbox.unwrap_or(true),
    })
}

/// V-15 — where an archive-mode install gets its bytes: a local file path or
/// a direct archive URL. No registry resolution, no signature, no cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveOrigin {
    LocalPath(PathBuf),
    DirectUrl(String),
}

/// The prominent no-guarantee notice every archive-mode install prints once
/// the actual sha256 is known. Exposed so tests pin the exact wording.
pub fn format_local_archive_notice(sha256_hex: &str) -> String {
    format!(
        "⚠ local archive: no registry signature / published-sha256 guarantee applies \
         (computed sha256: {sha256_hex})"
    )
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// D8 for direct archive URLs (V-15): there is no source config here, so the
/// `--allow-unsigned` install flag IS the operator consent. https:// passes
/// unconditionally; plain http:// needs the flag.
fn ensure_direct_url_allowed(url: &str, allow_http: bool) -> Result<(), VynmError> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") && allow_http {
        tracing::warn!("direct archive URL uses insecure http:// — allowed by --allow-unsigned");
        return Ok(());
    }
    Err(VynmError::Internal(
        "refusing insecure http:// direct archive download — pass --allow-unsigned to accept \
         unencrypted transports"
            .into(),
    ))
}

/// Best-effort pre-extraction peek at plugin.json's plugin_id so the archive
/// pipeline knows its slug before anything is extracted. None = absent or
/// unreadable; the authoritative refusal then comes from validating the
/// staged copy, exactly like a malformed manifest.
fn peek_plugin_id(bytes: &[u8]) -> Option<String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).ok()?;
    let mut entry = zip.by_name("plugin.json").ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    value.get("plugin_id")?.as_str().map(str::to_string)
}

/// V-15 — execute the archive-install pipeline for a local zip file or a
/// direct archive URL: acquire bytes → sha256 → extract → validate on the
/// staged copy → permission-confirm gate (V-10) → swap → record with
/// `source: "local"`. Deliberately SKIPS the revocation gate, entry-signature
/// check and registry cache — there is no registry in this flow; the printed
/// [`format_local_archive_notice`] states what that costs the operator.
/// Drop-in writing stays with the caller, same as [`install`].
pub async fn install_archive(
    origin: &ArchiveOrigin,
    tmp_dir: &Path,
    max_archive_bytes: u64,
    max_extracted_bytes: u64,
    max_archive_entries: usize,
    allow_http: bool,
    confirm: impl FnOnce(&InstallManifest) -> Result<(), VynmError>,
) -> Result<InstalledPlugin, VynmError> {
    // Step 1 — acquire bytes. Direct URL downloads only AFTER the D8 gate:
    // no byte may move before consent, mirroring the registry pipeline.
    let (bytes, source_url) = match origin {
        ArchiveOrigin::LocalPath(path) => {
            let meta = fs::metadata(path).map_err(VynmError::Io)?;
            if meta.len() > max_archive_bytes {
                return Err(VynmError::Internal(format!(
                    "archive size {} exceeds max {max_archive_bytes} bytes",
                    meta.len()
                )));
            }
            (fs::read(path)?, path.display().to_string())
        }
        ArchiveOrigin::DirectUrl(url) => {
            ensure_direct_url_allowed(url, allow_http)?;
            (
                download_with_progress(url, "archive", max_archive_bytes).await?,
                url.clone(),
            )
        }
    };

    // Step 2 — NO channel guarantee here: compute the real digest and say so,
    // prominently, before any validation decision.
    let actual_hash = hex_encode(&Sha256::digest(&bytes));
    eprintln!("{}", format_local_archive_notice(&actual_hash));

    // Staging key: the manifest's plugin_id, peeks out of the archive without
    // extracting. Unparsable manifests still stage (under a neutral name) so
    // validate_manifest produces the canonical refusal and cleanup erases it.
    let slug = peek_plugin_id(&bytes).unwrap_or_else(|| "archive".to_string());

    let plugin_base = plugin_dir(tmp_dir);
    let stage_dir = tmp_install_dir(&plugin_base, &slug);
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir).map_err(VynmError::Io)?;

    let archive_path = stage_dir.join(format!("{slug}.zip"));
    if let Err(e) = fs::write(&archive_path, &bytes) {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(VynmError::Io(e));
    }

    // Steps 3+ — identical boundaries to the registry pipeline (V-10 gate,
    // bak/rename swap, ledger record, tree digest); no revocation/signature/
    // cache steps exist here by design.
    commit_staged(
        tmp_dir,
        &stage_dir,
        &slug,
        None, // D2: kernel compat re-validated authoritatively at boot
        actual_hash,
        crate::state::LOCAL_SOURCE,
        &source_url,
        max_extracted_bytes,
        max_archive_entries,
        confirm,
    )
}

/// R10-02 — skip the whole install pipeline when the state store says `slug`
/// is already installed at `version` *and* the install dir still exists. A
/// missing dir (half-deleted install) falls through so `install` repairs it.
/// Rebuilds `InstalledPlugin` from the live manifest so the caller can still
/// write the auto-spawn drop-in config.
pub fn skip_reinstall(
    tmp_dir: &Path,
    slug: &str,
    version: &str,
    dest: &Path,
) -> Option<InstalledPlugin> {
    let state = load_state(tmp_dir);
    let tracked = state.get(slug)?;
    if tracked.version != version || !dest.exists() {
        return None;
    }
    // No authoritative kernel version here (D2) — range check belongs to the
    // kernel at boot; everything else in the manifest was validated at
    // install time and is re-checked now.
    let manifest = validate_manifest(
        &dest.join("plugin.json"),
        None,
        vynkor_wire::manifest::default_resolver,
    )
    .ok()?;
    // V-13 — repair path stays honest: re-digest the tree that is actually
    // on disk and refresh the record, so `verify` never blesses a stale
    // baseline after a same-version reinstall repaired the dir.
    if let Ok(actual) = tree_digest(dest) {
        if tracked.tree_sha256.as_deref() != Some(actual.as_str()) {
            let mut updated = tracked.clone();
            updated.tree_sha256 = Some(actual);
            // best-effort: a failed refresh warns but must not fail the skip
            if let Err(e) = record_install(tmp_dir, updated) {
                tracing::warn!("could not refresh tree digest for '{slug}': {e}");
            }
        }
    }
    Some(InstalledPlugin {
        slug: slug.to_string(),
        plugin_id: manifest.plugin_id,
        version: manifest.version,
        binary_path: dest.join(manifest.binary),
        sandbox_hint: manifest.sandbox.unwrap_or(true),
    })
}

/// V-10 — human-readable permission preview for the install confirmation
/// gate: declared permissions plus every action's caller requirement (v2
/// per-action permission, `unrestricted` when absent or legacy string).
pub fn format_permission_preview(manifest: &InstallManifest) -> String {
    let mut out = String::new();
    if manifest.permissions.is_empty() {
        out.push_str("permissions: (none)\n");
    } else {
        out.push_str(&format!(
            "permissions: {}\n",
            manifest.permissions.join(", ")
        ));
    }
    for spec in manifest.actions.iter().flatten() {
        out.push_str(&format!(
            "  {} -> {}\n",
            spec.name(),
            spec.permission().unwrap_or("unrestricted")
        ));
    }
    out
}

async fn download_with_progress(
    url: &str,
    slug: &str,
    max_archive_bytes: u64,
) -> Result<Vec<u8>, VynmError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| VynmError::Network(format!("download {slug}: {e}")))?;

    if !resp.status().is_success() {
        return Err(VynmError::Network(format!(
            "download {slug}: HTTP {}",
            resp.status()
        )));
    }

    if let Some(len) = resp.content_length() {
        if len > max_archive_bytes {
            return Err(VynmError::Internal(format!(
                "download {slug}: archive size {len} exceeds max {max_archive_bytes} bytes"
            )));
        }
    }

    let total = resp.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .map_err(|e| VynmError::Internal(format!("progress template: {e}")))?
        .progress_chars("#>-"),
    );

    let mut bytes: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| VynmError::Network(format!("stream {slug}: {e}")))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > max_archive_bytes {
            pb.finish_and_clear();
            return Err(VynmError::Internal(format!(
                "download {slug}: archive exceeds max {max_archive_bytes} bytes"
            )));
        }
        pb.inc(chunk.len() as u64);
        bytes.extend_from_slice(&chunk);
    }
    pb.finish_and_clear();

    Ok(bytes)
}

/// Manifest v2 `files` extraction allowlist, read from `plugin.json` inside
/// the archive without extracting it. Returns `None` when there is no
/// allowlist (no plugin.json, no `files` key, empty list, or any read/parse
/// error) — the caller then falls back to extract-everything.
fn read_files_allowlist(archive: &Path) -> Option<HashSet<String>> {
    let file = fs::File::open(archive).ok()?;
    let mut zip = zip::ZipArchive::new(file).ok()?;
    let mut entry = zip.by_name("plugin.json").ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    let files = value.get("files")?.as_array()?;
    let set: HashSet<String> = files
        .iter()
        .filter_map(|f| f.as_str().map(str::to_string))
        .collect();
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

/// Security boundary — ported verbatim from the kernel installer:
/// zip-slip rejection (absolute paths / `..` / prefix components), symlink
/// skipping, post-create containment re-checks, decompressed-size cap
/// enforced on actual copied bytes (a zip bomb lies about declared sizes),
/// and unix-mode restoration so binaries stay executable.
pub fn extract_zip(
    archive: &Path,
    dest: &Path,
    max_extracted_bytes: u64,
    max_archive_entries: usize,
    allowlist: Option<&HashSet<String>>,
) -> Result<(), VynmError> {
    let file = fs::File::open(archive).map_err(VynmError::Io)?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| VynmError::Internal(format!("open zip: {e}")))?;

    if zip.len() > max_archive_entries {
        return Err(VynmError::Verification(format!(
            "Malformed archive: {} entries exceeds max {max_archive_entries}. Aborting.",
            zip.len()
        )));
    }

    let canon_dest = dest.canonicalize().map_err(VynmError::Io)?;
    let mut total_extracted: u64 = 0;

    // Allowlisted names not yet seen in the archive; empty when no allowlist.
    let mut missing: HashSet<String> = allowlist.cloned().unwrap_or_default();

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| VynmError::Internal(format!("read zip entry: {e}")))?;
        let name = entry.name().to_owned();

        // Reject absolute paths, ".." components, and Windows prefix/root components.
        let candidate = Path::new(&name);
        let unsafe_components = candidate.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        });
        if candidate.is_absolute() || unsafe_components {
            return Err(VynmError::Verification(format!(
                "Malformed archive: path traversal detected in entry '{name}'. Aborting."
            )));
        }

        // Manifest v2 `files` allowlist: skip entries not named in it. The
        // zip-slip check above still applies to every entry, allowlisted or not.
        if let Some(list) = allowlist {
            if !list.contains(&name) {
                continue;
            }
            missing.remove(&name);
        }

        // Skip symlinks — do not follow them during extraction.
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                continue;
            }
        }

        let out = dest.join(candidate);

        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(VynmError::Io)?;
            // Verify dir stayed inside dest after creation (catches symlink races).
            let canon_out = out.canonicalize().map_err(VynmError::Io)?;
            if !canon_out.starts_with(&canon_dest) {
                return Err(VynmError::Verification(format!(
                    "Malformed archive: entry '{name}' escapes extraction dir. Aborting."
                )));
            }
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent).map_err(VynmError::Io)?;
                let canon_parent = parent.canonicalize().map_err(VynmError::Io)?;
                if !canon_parent.starts_with(&canon_dest) {
                    return Err(VynmError::Verification(format!(
                        "Malformed archive: entry '{name}' escapes extraction dir. Aborting."
                    )));
                }
            }
            let mut out_file = fs::File::create(&out).map_err(VynmError::Io)?;
            // Cap on actual bytes written, not the entry's declared/compressed
            // size — a zip bomb lies about (or omits) the true decompressed
            // size, so the limit must be enforced on the copy itself.
            let budget = max_extracted_bytes.saturating_sub(total_extracted) + 1;
            let written = std::io::copy(&mut entry.by_ref().take(budget), &mut out_file)
                .map_err(VynmError::Io)?;
            total_extracted += written;
            if total_extracted > max_extracted_bytes {
                return Err(VynmError::Verification(format!(
                    "Malformed archive: decompressed size exceeds max {max_extracted_bytes} bytes. Aborting."
                )));
            }
            // restore stored unix mode (exec bit) — fs::File::create gives 0644,
            // so a plugin binary would otherwise extract non-executable
            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&out, fs::Permissions::from_mode(mode & 0o7777))
                    .map_err(VynmError::Io)?;
            }
        }
    }

    if let Some(missing_name) = missing.iter().next() {
        return Err(VynmError::Verification(format!(
            "Malformed archive: manifest `files` lists '{missing_name}' which is missing from the archive. Aborting."
        )));
    }

    Ok(())
}
