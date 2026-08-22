use std::collections::HashSet;
use std::fs;
use std::io::Read;
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
use veyron_wire::manifest::validate_manifest;

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
    if let Err(e) = veyron_wire::manifest::check_kernel_compatibility(
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
/// resolve → revoke-gate → signature → download → digest → extract → swap →
/// validate → record. Drop-in writing stays with the caller (V-06).
#[allow(clippy::too_many_arguments)]
pub async fn install(
    entries: &[RegistryEntry],
    target: &str,
    source: &RegistrySource,
    tmp_dir: &Path,
    max_archive_bytes: u64,
    max_extracted_bytes: u64,
    max_archive_entries: usize,
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
        return Err(VynmError::Internal(format!(
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
        return Err(VynmError::Internal(format!(
            "Archive integrity check failed. Expected {}, got {}. Aborting — do not proceed.",
            entry.sha256, actual_hash
        )));
    }

    // Step 6 — Extract to temporary folder (zip-slip protection)
    let extract_dir = stage_dir.join("extracted");
    if let Err(e) = fs::create_dir_all(&extract_dir) {
        let _ = fs::remove_dir_all(&stage_dir);
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
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(e);
    }

    // Step 7 — Atomic move to plugin directory
    if let Err(e) = fs::create_dir_all(&plugin_base) {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(VynmError::Io(e));
    }

    let bak = plugin_base.join(format!("{}.bak", entry.slug));
    let had_existing = dest.exists();

    if had_existing {
        if bak.exists() {
            let _ = fs::remove_dir_all(&bak);
        }
        if let Err(e) = fs::rename(&dest, &bak) {
            let _ = fs::remove_dir_all(&stage_dir);
            return Err(VynmError::Io(e));
        }
    }

    if let Err(e) = fs::rename(&extract_dir, &dest) {
        if had_existing {
            let _ = fs::rename(&bak, &dest);
        }
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(VynmError::Io(e));
    }

    // Step 8 — Final validation of plugin.json. Kernel version comes from the
    // pre-flight probe (Some → range checked; None → skipped per D2); the
    // permission policy is the wire default_resolver.
    let manifest_path = dest.join("plugin.json");
    let manifest = match validate_manifest(
        &manifest_path,
        kernel_ver.as_ref(),
        veyron_wire::manifest::default_resolver,
    ) {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_dir_all(&dest);
            if had_existing {
                let _ = fs::rename(&bak, &dest);
            }
            let _ = fs::remove_dir_all(&stage_dir);
            return Err(VynmError::Internal(e.to_string()));
        }
    };

    if had_existing {
        let _ = fs::remove_dir_all(&bak);
    }
    let _ = fs::remove_dir_all(&stage_dir);

    // R10-02 — record in the explicit state store; a plugin on disk but
    // untracked is exactly the drift this store exists to prevent. §6.2: the
    // origin source name rides along for future update resolution.
    record_install(
        tmp_dir,
        InstalledEntry {
            slug: entry.slug.clone(),
            version: manifest.version.clone(),
            sha256: actual_hash,
            installed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            source_url: source.url.clone(),
            source: source.name.clone(),
        },
    )?;

    Ok(InstalledPlugin {
        slug: entry.slug.clone(),
        plugin_id: manifest.plugin_id.clone(),
        version: manifest.version.clone(),
        binary_path: dest.join(&manifest.binary),
        sandbox_hint: manifest.sandbox.unwrap_or(true),
    })
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
        veyron_wire::manifest::default_resolver,
    )
    .ok()?;
    Some(InstalledPlugin {
        slug: slug.to_string(),
        plugin_id: manifest.plugin_id,
        version: manifest.version,
        binary_path: dest.join(manifest.binary),
        sandbox_hint: manifest.sandbox.unwrap_or(true),
    })
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
        return Err(VynmError::Internal(format!(
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
            return Err(VynmError::Internal(format!(
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
                return Err(VynmError::Internal(format!(
                    "Malformed archive: entry '{name}' escapes extraction dir. Aborting."
                )));
            }
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent).map_err(VynmError::Io)?;
                let canon_parent = parent.canonicalize().map_err(VynmError::Io)?;
                if !canon_parent.starts_with(&canon_dest) {
                    return Err(VynmError::Internal(format!(
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
                return Err(VynmError::Internal(format!(
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
        return Err(VynmError::Internal(format!(
            "Malformed archive: manifest `files` lists '{missing_name}' which is missing from the archive. Aborting."
        )));
    }

    Ok(())
}
