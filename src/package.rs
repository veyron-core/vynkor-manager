//! `vynm package <dir>` (V-14 follow-up backlog): turn a BUILT plugin
//! directory into the distribution artifacts `scripts/package.sh` produces —
//! the release zip, `checksum.sha256`, the S1 `signature.sig`, the `dist/`
//! layout, `dist/<slug>/latest.json`, and the v2 `registry.json` upsert.
//!
//! Deliberate scope decisions (documented deviations):
//! - NO `cargo build`: vynm packages what already exists — `manifest.binary`
//!   must be present under `<dir>`; build orchestration belongs to the
//!   plugins repo CI, not the marketplace manager.
//! - NO `-src.zip` (follow-up); the four steps the backlog names — zip +
//!   checksum + sign + upsert — are all covered.
//! - Signing is optional exactly like package.sh: no `--key` ⇒ empty
//!   signature (`vynm install` rejects the entry until it is signed) and no
//!   `signature.sig` file.
//!
//! The canonical message is NEVER formatted here: the entry is assembled and
//! handed to [`crate::registry::signed_message`] via [`crate::sign`], the
//! single source of truth pinned by tests (lesson #1 in
//! docs/STAGE4_MANAGER_WAVES.md).

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use semver::Version;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::error::VynmError;
use crate::registry::{hex_encode, verify_entry_signature, RegistryEntry};
use crate::sign;
use crate::source::official_source;
use crate::state::format_ts;
use crate::validate::validate_identifier;
use vynkor_wire::manifest::{default_resolver, validate_manifest, InstallManifest};

/// Everything `vynm package` needs. Display metadata (name/description/
/// category/tags/status/source_url) lands verbatim in the registry entry,
/// mirroring package.sh's positional + optional arguments.
pub struct PackageOpts<'a> {
    /// Directory containing a valid `plugin.json` and the built binary.
    pub dir: &'a Path,
    /// Root that holds `dist/` and `registry.json` (the plugins repo root).
    pub repo_root: &'a Path,
    pub name: &'a str,
    pub description: &'a str,
    pub category: &'a str,
    pub tags: &'a [String],
    pub status: &'a str,
    pub source_url: &'a str,
    /// Optional hex-seed signing key file — omit for an unsigned entry.
    pub key: Option<&'a Path>,
    /// Replace an existing archive / overwrite registry versions.
    pub force: bool,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_file(path: &Path) -> Result<String, VynmError> {
    let bytes = fs::read(path)?;
    Ok(hex_encode(&Sha256::digest(&bytes)))
}

/// Resolve which files go into the archive. Manifest v2 `files` allowlist
/// wins when declared (and must cover the binary + plugin.json, same rule as
/// package.sh); otherwise the legacy pair `[binary, plugin.json]`.
/// Archive entries are FLAT (basename only) — `zip -j` parity with
/// package.sh and with what `extract_zip` expects at extraction root.
fn collect_archive_files(
    dir: &Path,
    manifest: &InstallManifest,
) -> Result<Vec<(String, PathBuf)>, VynmError> {
    let mut wanted: Vec<String> = if manifest.files.is_empty() {
        vec![manifest.binary.clone(), "plugin.json".into()]
    } else {
        let files = manifest.files.clone();
        let binary = manifest.binary.clone();
        let plugin_json = "plugin.json".to_string();
        for required in [&binary, &plugin_json] {
            if !files.iter().any(|f| f == required) {
                return Err(VynmError::InvalidInput(format!(
                    "manifest `files` must include '{required}' (the kernel requires it)"
                )));
            }
        }
        files
    };
    wanted.sort();

    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for rel in wanted {
        let source = dir.join(&rel);
        if !source.is_file() {
            return Err(VynmError::InvalidInput(format!(
                "'{rel}' not found under {}",
                dir.display()
            )));
        }
        let base = Path::new(&rel)
            .file_name()
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_else(|| rel.clone());
        if out.iter().any(|(name, _)| name == &base) {
            return Err(VynmError::InvalidInput(format!(
                "duplicate archive basename '{base}' — flat archives cannot carry it"
            )));
        }
        out.push((base, source));
    }
    Ok(out)
}

fn write_zip(files: &[(String, PathBuf)], dest: &Path) -> Result<(), VynmError> {
    let file = fs::File::create(dest).map_err(VynmError::Io)?;
    let mut zip = ZipWriter::new(file);
    let base_opts =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, source) in files {
        // Preserve the on-disk mode so the exec bit survives packaging —
        // tree_digest treats exec-bit changes as tampering (V-13).
        let mode = fs::metadata(source)?.permissions().mode() & 0o7777;
        zip.start_file(name.as_str(), base_opts.unix_permissions(mode))
            .map_err(|e| VynmError::Internal(format!("zip: {e}")))?;
        let bytes = fs::read(source)?;
        zip.write_all(&bytes).map_err(VynmError::Io)?;
    }
    zip.finish()
        .map_err(|e| VynmError::Internal(format!("zip: {e}")))?;
    Ok(())
}

/// Today as `YYYY-MM-DD` UTC (registry `meta.lastUpdated`), reusing the
/// dependency-free formatter — one date logic, never forked.
fn today() -> String {
    format_ts(now_secs())[..10].to_string()
}

/// Upsert the signed version into the v2 registry document, preserving
/// `meta` (apiVersion/lastUpdated refreshed), `revoked`, and every other
/// slug untouched; top-level key order rebuilt canonically as
/// meta, revoked, slugs alphabetically (byte-parity with package.sh).
fn upsert_registry(
    registry_path: &Path,
    slug: &str,
    opts: &PackageOpts<'_>,
    version_entry: &RegistryEntry,
    requires: &[String],
) -> Result<(), VynmError> {
    use serde_json::{Map, Value};

    let root: Map<String, Value> = if !registry_path.exists() {
        Map::new()
    } else {
        let text = fs::read_to_string(registry_path).map_err(VynmError::Io)?;
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(map)) => map,
            Ok(_) => {
                return Err(VynmError::InvalidInput(format!(
                    "{} is not a v2 map-form registry document — refusing to touch it",
                    registry_path.display()
                )))
            }
            Err(e) => {
                return Err(VynmError::InvalidInput(format!(
                    "{} does not parse as JSON ({e}) — fix or back it up before packaging",
                    registry_path.display()
                )))
            }
        }
    };

    let mut meta = root
        .get("meta")
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Map::new()));
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("apiVersion".into(), Value::from(2));
        obj.insert("lastUpdated".into(), Value::from(today()));
    }

    let revoked = root
        .get("revoked")
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![]));

    // Everything that is neither meta nor revoked is a slug entry.
    let mut slugs: Map<String, Value> = root
        .into_iter()
        .filter(|(k, _)| k != "meta" && k != "revoked")
        .collect();

    let entry = slugs
        .get(slug)
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Map::new()));
    let entry_obj = entry.as_object().expect("filtered to object above");

    let mut new_entry = Map::new();
    new_entry.insert("name".into(), Value::from(opts.name));
    new_entry.insert("description".into(), Value::from(opts.description));
    new_entry.insert("category".into(), Value::from(opts.category));
    new_entry.insert(
        "tags".into(),
        Value::Array(opts.tags.iter().map(|t| Value::from(t.as_str())).collect()),
    );
    new_entry.insert("status".into(), Value::from(opts.status));
    new_entry.insert("source_url".into(), Value::from(opts.source_url));
    // Carry over anything the maintainer had beyond the fields we own.
    for (k, v) in entry_obj {
        if !new_entry.contains_key(k) && k != "versions" {
            new_entry.insert(k.clone(), v.clone());
        }
    }

    let mut versions: Map<String, Value> = entry_obj
        .get("versions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut version_obj = Map::new();
    version_obj.insert(
        "archive_url".into(),
        Value::from(version_entry.archive_url.as_str()),
    );
    version_obj.insert("sha256".into(), Value::from(version_entry.sha256.as_str()));
    version_obj.insert(
        "signature".into(),
        Value::from(version_entry.signature.as_str()),
    );
    version_obj.insert(
        "min_kernel_version".into(),
        Value::from(version_entry.min_kernel_version.as_str()),
    );
    version_obj.insert(
        "max_kernel_version".into(),
        Value::from(version_entry.max_kernel_version.as_str()),
    );
    if !requires.is_empty() {
        // package.sh parity: declared deps become a dependencies map with the
        // default ">=0.0.0" range.
        let deps: Map<String, Value> = requires
            .iter()
            .map(|dep| (dep.clone(), Value::from(">=0.0.0")))
            .collect();
        version_obj.insert("dependencies".into(), Value::Object(deps));
    }
    versions.insert(version_entry.version.clone(), Value::Object(version_obj));
    new_entry.insert("versions".into(), Value::Object(versions));

    slugs.insert(slug.to_string(), Value::Object(new_entry));

    // Canonical order: meta, revoked, then slugs alphabetically (preserve_order).
    let mut out = Map::new();
    out.insert("meta".into(), meta);
    out.insert("revoked".into(), revoked);
    let sorted: BTreeSet<String> = slugs.keys().cloned().collect();
    for key in sorted {
        if let Some(v) = slugs.remove(&key) {
            out.insert(key, v);
        }
    }

    let json = serde_json::to_string_pretty(&Value::Object(out))
        .map_err(|e| VynmError::Internal(format!("serialize registry: {e}")))?;
    let tmp = registry_path.with_extension("json.tmp");
    fs::write(&tmp, format!("{json}\n")).map_err(VynmError::Io)?;
    fs::rename(&tmp, registry_path).map_err(VynmError::Io)?;
    Ok(())
}

/// Highest registered semver including `current` — feeds
/// `dist/<slug>/latest.json`. Unparsable versions never win; when nothing
/// parses, `current` wins.
fn latest_version(existing_versions: &[&str], current: &str) -> String {
    let mut best = Version::parse(current).ok();
    for v in existing_versions
        .iter()
        .filter_map(|v| Version::parse(v).ok())
    {
        match &best {
            Some(b) if *b >= v => {}
            _ => best = Some(v),
        }
    }
    best.map(|b| b.to_string())
        .unwrap_or_else(|| current.to_string())
}

/// Run the full packaging pipeline; prints a human report.
pub fn run(opts: PackageOpts<'_>) -> Result<(), VynmError> {
    if !opts.dir.is_dir() {
        return Err(VynmError::InvalidInput(format!(
            "'{}': not a directory",
            opts.dir.display()
        )));
    }
    let manifest = validate_manifest(&opts.dir.join("plugin.json"), None, default_resolver)
        .map_err(|e| VynmError::InvalidInput(format!("invalid plugin.json: {e}")))?;

    let slug = manifest.plugin_id.clone();
    validate_identifier(&slug, 64).map_err(|e| {
        VynmError::InvalidInput(format!("invalid plugin_id '{slug}' in manifest: {e}"))
    })?;
    let version = manifest.version.clone();

    let dist_dir = opts.repo_root.join("dist");
    let version_dir = dist_dir.join(&slug).join("versions").join(&version);
    let archive_name = format!("{slug}-{version}.zip");
    let archive_path = version_dir.join(&archive_name);

    if archive_path.exists() && !opts.force {
        return Err(VynmError::InvalidInput(format!(
            "{} already exists — pass --force to replace it",
            archive_path.display()
        )));
    }

    let files = collect_archive_files(opts.dir, &manifest)?;
    fs::create_dir_all(&version_dir).map_err(VynmError::Io)?;
    let _ = fs::remove_file(&archive_path);
    write_zip(&files, &archive_path)?;

    let sha256 = sha256_file(&archive_path)?;

    // "<sha256>  <archive>" (two spaces) — `sha256sum -c` compatible.
    fs::write(
        version_dir.join("checksum.sha256"),
        format!("{sha256}  {archive_name}\n"),
    )
    .map_err(VynmError::Io)?;
    // Browse copy of the manifest next to the archive.
    fs::copy(
        opts.dir.join("plugin.json"),
        version_dir.join("plugin.json"),
    )
    .map_err(VynmError::Io)?;

    // Relative archive_url — resolved against the registry's own base URL by
    // the installer, so host migration never breaks signatures (the S1
    // message covers the URL AS WRITTEN).
    let archive_url = format!("dist/{slug}/versions/{version}/{archive_name}");
    let range = &manifest.kernel_compatibility_range;

    let mut entry = sign::entry_from_fields(
        &slug,
        &version,
        &sha256,
        opts.status,
        &archive_url,
        &range.min,
        &range.max,
    );

    match opts.key {
        Some(key_path) => {
            let key = sign::load_signing_key(key_path)?;
            let signature = sign::sign_entry(&key, &entry);
            // Self-check: what we are about to publish MUST verify against
            // the key that produced it (package.sh parity — fail loudly).
            entry.signature = signature.clone();
            let derived_pk = hex_encode(&key.verifying_key().to_bytes());
            verify_entry_signature(&entry, &derived_pk)?;
            if official_source().public_key.as_deref() != Some(derived_pk.as_str()) {
                eprintln!(
                    "warning: signing key public key {derived_pk} does not match the \
                     pinned maintainer public key — `vynm install` will reject this \
                     entry until it is re-signed with the correct key"
                );
            }
            fs::write(version_dir.join("signature.sig"), format!("{signature}\n"))
                .map_err(VynmError::Io)?;
            println!("✓ signed {slug}@{version}");
        }
        None => {
            eprintln!(
                "warning: no --key given — the registry entry gets an EMPTY signature; \
                 `vynm install` will reject it until it is signed"
            );
        }
    }

    let registry_path = opts.repo_root.join("registry.json");
    let previous_versions: Vec<String> = fs::read_to_string(&registry_path)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|doc| doc.get(&slug)?.get("versions")?.as_object().cloned())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    let refs: Vec<&str> = previous_versions.iter().map(String::as_str).collect();
    let latest = latest_version(&refs, &version);
    let latest_dir = dist_dir.join(&slug);
    fs::create_dir_all(&latest_dir).map_err(VynmError::Io)?;
    let latest_json = serde_json::json!({ "version": latest }).to_string();
    fs::write(latest_dir.join("latest.json"), format!("{latest_json}\n")).map_err(VynmError::Io)?;

    upsert_registry(&registry_path, &slug, &opts, &entry, &manifest.requires)?;

    println!("✓ packaged {}", archive_path.display());
    println!("  sha256:      {sha256}");
    println!("  archive_url: {archive_url}");
    if entry.signature.is_empty() {
        println!("  signature:   (none — unsigned entry)");
    } else {
        println!("  signature:   {}…", &entry.signature[..16]);
    }
    println!("  registry:    {}", registry_path.display());
    println!("  latest:      {latest}");
    Ok(())
}

#[cfg(test)]
#[path = "package_tests.rs"]
mod tests;
