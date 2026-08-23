//! vynm CLI (V-06). The kernel-side `vyn plugin install|search|…` shims exec
//! this binary with forwarded args once V-07 lands, so the grammar here is a
//! user-facing contract: subcommands take `--source <name>` from day one
//! (§6.5 — adding sources later changes resolution logic, never grammar).

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::Deserialize;

use crate::dropin::{
    disable_plugin_config, enable_plugin_config, plugin_dir, remove_plugin_config, uninstall,
    write_plugin_config, DropinParams, Toggle,
};
use crate::error::VynmError;
use crate::installer::install;
use crate::registry::{fetch_registry, RegistryEntry};
use crate::source::{official_source, RegistrySource};
use crate::state::{format_ts, load_state};

// ── exit codes — the scripting contract (0 ok / 1 failure / 2 network /
// 3 verification; finalized in V-16) ─────────────────────────────────────────

pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_NETWORK: i32 = 2;
pub const EXIT_VERIFICATION: i32 = 3;

/// Map an error onto the scripting contract. Ported security refusals raise
/// `Internal` carrying the kernel-verbatim message texts, so verification-
/// class failures are recognized by their canonical wording here until V-16
/// restructures error variants if needed.
pub fn exit_code(err: &VynmError) -> i32 {
    match err {
        VynmError::Network(_) => EXIT_NETWORK,
        VynmError::Internal(m)
            if m.contains("signature")
                || m.contains("integrity check failed")
                || m.contains("revoked by the maintainer")
                || m.contains("Malformed archive")
                || m.contains("path traversal") =>
        {
            EXIT_VERIFICATION
        }
        _ => EXIT_FAILURE,
    }
}

// ── config: the kernel's own yaml, minimally read ───────────────────────────

/// cache_ttl_secs default for a `registries:` entry that omits it — same
/// value as the built-in official source.
const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

fn default_true() -> bool {
    true
}

/// One `registries:` list entry (V-09). `public_key` absent = unsigned
/// source (§7.3 consent still required before content is accepted).
#[derive(Debug, Deserialize)]
struct RawRegistry {
    name: String,
    url: String,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    allow_unsigned: bool,
    #[serde(default)]
    cache_ttl_secs: Option<u64>,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// Only the keys vynm consumes. Unknown keys are ignored on purpose — vynm
/// must tolerate every future kernel config addition. V-09: `registries:`
/// list plus the legacy single keys kept for back-compat; when both appear
/// the list wins wholesale (legacy keys only map onto an `official` source
/// when no list is present).
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    plugins_dir: Option<PathBuf>,
    #[serde(default)]
    registry_url: Option<String>,
    #[serde(default)]
    marketplace_public_key: Option<String>,
    #[serde(default)]
    registry_cache_ttl_secs: Option<u64>,
    #[serde(default)]
    allow_unsigned: Option<bool>,
    #[serde(default)]
    registries: Vec<RawRegistry>,
}

/// Map parsed config onto the configured source list:
/// `registries:` list > back-compat single keys > built-in official default.
/// Duplicate names are a hard error naming both entries.
fn build_sources(raw: &RawConfig) -> Result<Vec<RegistrySource>, String> {
    if raw.registries.is_empty() {
        let mut s = official_source();
        // back-compat single keys override the official entry's fields
        if let Some(url) = &raw.registry_url {
            s.url = url.clone();
        }
        if let Some(key) = &raw.marketplace_public_key {
            s.public_key = Some(key.clone());
        }
        if let Some(ttl) = raw.registry_cache_ttl_secs {
            s.cache_ttl_secs = ttl;
        }
        if let Some(a) = raw.allow_unsigned {
            s.allow_unsigned = a;
        }
        return Ok(vec![s]);
    }
    let mut out: Vec<RegistrySource> = Vec::with_capacity(raw.registries.len());
    for (i, r) in raw.registries.iter().enumerate() {
        if r.name.trim().is_empty() {
            return Err(format!("registries[{}]: name must be non-empty", i + 1));
        }
        if r.url.trim().is_empty() {
            return Err(format!(
                "registries[{}] ({}): url must be non-empty",
                i + 1,
                r.name
            ));
        }
        if let Some(prev) = out.iter().position(|s| s.name == r.name) {
            return Err(format!(
                "duplicate registry name '{}' (entries {} and {})",
                r.name,
                prev + 1,
                i + 1
            ));
        }
        out.push(RegistrySource {
            name: r.name.clone(),
            url: r.url.clone(),
            public_key: r.public_key.clone(),
            allow_unsigned: r.allow_unsigned,
            cache_ttl_secs: r.cache_ttl_secs.unwrap_or(DEFAULT_CACHE_TTL_SECS),
            enabled: r.enabled,
        });
    }
    Ok(out)
}

/// Precedence tier between CLI flags and config: env vars override the
/// effective (first) source's fields in place — the name is kept so per-source
/// caches and ledger origins stay stable. Empty values are ignored so a
/// stray `VYNM_REGISTRY_URL=""` cannot blank a good URL.
fn apply_env_overrides(sources: &mut [RegistrySource]) {
    let Some(first) = sources.first_mut() else {
        return;
    };
    if let Ok(url) = std::env::var("VYNM_REGISTRY_URL") {
        if !url.trim().is_empty() {
            first.url = url;
        }
    }
    if let Ok(key) = std::env::var("VYNM_MARKETPLACE_PUBLIC_KEY") {
        if !key.trim().is_empty() {
            first.public_key = Some(key);
        }
    }
}

/// Resolve the drop-in plugin dir — ported verbatim from the kernel's
/// `utils/config.rs` so both binaries derive `<config dir>/plugins.d` from
/// the same `--config` file. Explicit `plugins_dir:` key wins.
pub fn resolve_plugins_dir(config_path: &str, explicit: Option<&Path>) -> PathBuf {
    explicit.map(Path::to_path_buf).unwrap_or_else(|| {
        Path::new(config_path)
            .parent()
            .map(|p| p.join("plugins.d"))
            .unwrap_or_else(|| PathBuf::from("plugins.d"))
    })
}

/// Everything a command needs, resolved from `--config`.
#[derive(Debug)]
pub struct Ctx {
    pub plugins_dir: PathBuf,
    /// configured sources in listed order; `[0]` is the effective default.
    /// V-09: resolution (--source, bare-slug search, explicit `name/slug`)
    /// works over this list.
    pub sources: Vec<RegistrySource>,
    /// Fallback base for state/plugin dirs when `$HOME`/XDG are unset —
    /// private per-process scratch, never the shared world-writable /tmp root.
    pub tmp_dir: PathBuf,
}

fn scratch_base() -> PathBuf {
    std::env::temp_dir().join(format!("vynm-{}", std::process::id()))
}

impl Ctx {
    pub fn load(config_path: &str) -> Result<Self, VynmError> {
        let raw = match std::fs::read_to_string(config_path) {
            Ok(text) => serde_yaml::from_str::<RawConfig>(&text)
                .map_err(|e| VynmError::InvalidInput(format!("{}: {e}", config_path)))?,
            Err(_) => RawConfig::default(), // no config yet → pure defaults
        };
        let mut sources = build_sources(&raw)
            .map_err(|e| VynmError::InvalidInput(format!("{config_path}: {e}")))?;
        apply_env_overrides(&mut sources);
        Ok(Self {
            plugins_dir: resolve_plugins_dir(config_path, raw.plugins_dir.as_deref()),
            sources,
            tmp_dir: scratch_base(),
        })
    }

    /// configured source names, in listed order — error listings use this
    pub fn source_names(&self) -> Vec<&str> {
        self.sources.iter().map(|s| s.name.as_str()).collect()
    }

    /// §6.5: `--source <name>` exact-matches against the configured list;
    /// None → the effective default (`sources[0]`). Unknown → error listing
    /// all configured names.
    pub fn resolve_source(&self, requested: Option<&str>) -> Result<RegistrySource, VynmError> {
        match requested {
            None => Ok(self.sources[0].clone()),
            Some(name) => self
                .sources
                .iter()
                .find(|s| s.name == name)
                .cloned()
                .ok_or_else(|| {
                    VynmError::InvalidInput(format!(
                        "unknown source '{name}' — configured sources: {}",
                        self.source_names().join(", ")
                    ))
                }),
        }
    }
}

// install size caps — operator-tunable knobs land with V-09 config layering
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;

// ── clap surface ────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "vynm",
    version,
    about = "vynm — plugin marketplace manager for the Veyron/vynkor kernel"
)]
pub struct Cli {
    /// Path to the kernel's config.yaml — drop-ins and registries derive from it
    #[arg(long, global = true, default_value = "config.yaml")]
    pub config: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Install a plugin from a registry into the kernel's plugin tree
    Install {
        slug: String,
        /// Registry source name (see the configured sources)
        #[arg(long)]
        source: Option<String>,
    },
    /// Search the registry
    Search {
        query: String,
        #[arg(long)]
        source: Option<String>,
    },
    /// List installed plugins (from the local ledger)
    List {
        #[arg(long)]
        source: Option<String>,
    },
    /// Remove an installed plugin (dir + ledger record + drop-in)
    Remove { slug: String },
    /// Re-enable auto-spawn for an installed plugin
    Enable { slug: String },
    /// Stop auto-spawning an installed plugin (drop-in renamed .disabled)
    Disable { slug: String },
    /// Generate an ed25519 signing key pair for registry publishing (V-14)
    Keygen {
        /// Name for the default output path (<name>.key)
        name: Option<String>,
        /// Output path for the hex seed (default ./<name>.key)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite the key file if it already exists
        #[arg(long)]
        force: bool,
    },
    /// Scaffold a new plugin project (V-20)
    New {
        name: String,
        /// Overwrite files in an existing target dir
        #[arg(long)]
        force: bool,
    },
    /// Sign (or with --verify, check) a registry entry over the canonical
    /// seven-field message (V-14)
    Sign {
        /// Path to the hex-seed key file (from `vynm keygen`); required for
        /// signing, unused with --verify
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        slug: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        sha256: String,
        /// Lifecycle status baked into the signature
        #[arg(long, default_value = "stable")]
        status: String,
        #[arg(long)]
        archive_url: String,
        /// Minimum kernel version
        #[arg(long)]
        min: String,
        /// Maximum kernel version
        #[arg(long, default_value = "*")]
        max: String,
        /// Verify an existing signature instead of signing
        #[arg(long, requires = "public_key", requires = "signature")]
        verify: bool,
        /// Public key hex (verify mode)
        #[arg(long)]
        public_key: Option<String>,
        /// Signature hex to check (verify mode)
        #[arg(long)]
        signature: Option<String>,
    },
}

/// Dispatch a parsed invocation; errors bubble to main for exit-code mapping.
pub async fn run(cli: &Cli) -> Result<(), VynmError> {
    // keygen/sign/new are local ops — no config file, no network
    match &cli.command {
        Command::Keygen { name, out, force } => {
            return keygen_cmd(name.as_deref(), out.as_deref(), *force)
        }
        Command::New { name, force } => return new_cmd(name, *force),
        Command::Sign {
            key,
            slug,
            version,
            sha256,
            status,
            archive_url,
            min,
            max,
            verify,
            public_key,
            signature,
        } => {
            return sign_cmd(
                key.as_deref(),
                slug,
                version,
                sha256,
                status,
                archive_url,
                min,
                max,
                *verify,
                public_key.as_deref(),
                signature.as_deref(),
            )
        }
        _ => {}
    }
    let ctx = Ctx::load(&cli.config)?;
    match &cli.command {
        Command::Install { slug, source } => {
            let pinned = pin_source(&ctx, source.as_deref(), slug)?;
            install_cmd(&ctx, pinned.as_ref(), slug).await.map(|_| ())
        }
        Command::Search { query, source } => {
            let pinned = pin_source(&ctx, source.as_deref(), query)?;
            search_cmd(&ctx, pinned.as_ref(), query).await.map(|_| ())
        }
        Command::List { source } => list_cmd(&ctx, source.as_deref()),
        Command::Remove { slug } => remove_cmd(&ctx, slug),
        Command::Enable { slug } => enable_cmd(&ctx, slug),
        Command::Disable { slug } => disable_cmd(&ctx, slug),
        // all handled above, before Ctx::load
        Command::Keygen { .. } | Command::Sign { .. } | Command::New { .. } => Ok(()),
    }
}

// ── §7.2 resolution engine (V-09) ───────────────────────────────────────────

/// Which source a target resolved against, so commands can attribute it
/// (`resolved from <name>`) and tests can assert attribution without
/// scraping stdout.
pub struct ResolutionReceipt {
    pub source_name: String,
}

/// §7.2 target grammar: `corp/database` → Some(("corp", "database")). Slugs
/// never contain '/' (MA-17 charset), so the first slash is always the split;
/// anything else is a bare slug.
fn split_target(target: &str) -> Option<(&str, &str)> {
    match target.split_once('/') {
        Some((name, slug)) if !name.is_empty() && !slug.is_empty() => Some((name, slug)),
        _ => None,
    }
}

/// (--source flag, target) → explicitly pinned source, or None = generic
/// bare-slug resolution. Explicit forms never search: an unknown name errors
/// listing every configured source.
fn pin_source(
    ctx: &Ctx,
    flag: Option<&str>,
    target: &str,
) -> Result<Option<RegistrySource>, VynmError> {
    if let Some(name) = flag {
        return Ok(Some(ctx.resolve_source(Some(name))?));
    }
    match split_target(target) {
        Some((name, _)) => Ok(Some(ctx.resolve_source(Some(name))?)),
        None => Ok(None),
    }
}

/// Bare-slug probe order: enabled sources in listed order, except that a
/// ledger-recorded origin (§6.2) goes first — reinstalls/updates of an
/// installed plugin must hit the same channel it came from before generic
/// search can shadow it. A disabled or since-unconfigured origin falls out.
fn bare_slug_candidates(
    sources: &[RegistrySource],
    ledger_origin: Option<&str>,
) -> Vec<RegistrySource> {
    let mut out = Vec::new();
    if let Some(origin) = ledger_origin {
        if let Some(s) = sources.iter().find(|s| s.name == origin && s.enabled) {
            out.push(s.clone());
        }
    }
    for s in sources {
        if s.enabled && !out.iter().any(|o| o.name == s.name) {
            out.push(s.clone());
        }
    }
    out
}

enum ProbeOutcome {
    Found(RegistrySource, Vec<RegistryEntry>),
    NoMatch(Vec<String>),
}

/// Try candidates in order; the first source whose entries satisfy `wants`
/// wins. A fetch error skips to the next source (warned); when NO candidate
/// could be fetched at all, the last error propagates unchanged so exit-code
/// mapping (network=2 etc.) survives multi-source probing.
async fn probe_sources(
    candidates: &[RegistrySource],
    tmp_dir: &Path,
    wants: impl Fn(&[RegistryEntry]) -> bool,
) -> Result<ProbeOutcome, VynmError> {
    let mut last_err = None;
    let mut fetched_any = false;
    for src in candidates {
        match fetch_registry(src, false, tmp_dir).await {
            Ok(entries) => {
                fetched_any = true;
                if wants(&entries) {
                    return Ok(ProbeOutcome::Found(src.clone(), entries));
                }
            }
            Err(e) => {
                tracing::warn!(
                    "registry '{}': fetch failed ({e}) — moving to the next source",
                    src.name
                );
                last_err = Some(e);
            }
        }
    }
    if !fetched_any {
        return Err(last_err
            .unwrap_or_else(|| VynmError::Internal("no registry sources configured".into())));
    }
    Ok(ProbeOutcome::NoMatch(
        candidates.iter().map(|s| s.name.clone()).collect(),
    ))
}

async fn install_cmd(
    ctx: &Ctx,
    pinned: Option<&RegistrySource>,
    target: &str,
) -> Result<ResolutionReceipt, VynmError> {
    let slug = split_target(target).map(|(_, s)| s).unwrap_or(target);
    let (src, entries) = match pinned {
        Some(src) => {
            let entries = fetch_registry(src, false, &ctx.tmp_dir).await?;
            (src.clone(), entries)
        }
        None => {
            let ledger = load_state(&ctx.tmp_dir);
            let origin = ledger.get(slug).map(|e| e.source.as_str());
            let candidates = bare_slug_candidates(&ctx.sources, origin);
            match probe_sources(&candidates, &ctx.tmp_dir, |entries| {
                entries.iter().any(|e| e.slug == slug || e.id == slug)
            })
            .await?
            {
                ProbeOutcome::Found(src, entries) => (src, entries),
                ProbeOutcome::NoMatch(tried) => {
                    return Err(VynmError::Internal(format!(
                        "Plugin '{slug}' not found in any configured source (tried: {}). \
                         Run 'vynm search {slug}' to browse.",
                        tried.join(", ")
                    )));
                }
            }
        }
    };

    println!("resolved from {}", src.name);
    let installed = install(
        &entries,
        slug,
        &src,
        &ctx.tmp_dir,
        MAX_ARCHIVE_BYTES,
        MAX_EXTRACTED_BYTES,
        MAX_ARCHIVE_ENTRIES,
    )
    .await?;

    // D3: the manifest's own hint decides the drop-in default
    let params = DropinParams {
        slug: &installed.slug,
        plugin_id: &installed.plugin_id,
        binary_path: &installed.binary_path,
        sandbox: installed.sandbox_hint,
    };
    let written = write_plugin_config(&ctx.plugins_dir, &params)?;
    match written {
        true => println!(
            "   Auto-spawn entry: {}",
            ctx.plugins_dir
                .join(format!("{}.yaml", installed.slug))
                .display()
        ),
        false => println!(
            "   drop-in {} already exists — left untouched",
            ctx.plugins_dir
                .join(format!("{}.yaml", installed.slug))
                .display()
        ),
    }
    Ok(ResolutionReceipt {
        source_name: src.name,
    })
}

/// search hits for a lowercased query — shared by the probe predicate and
/// the table printer so both see exactly the same matches (owned clones: the
/// probe's registry document doesn't outlive resolution)
fn matching_entries(entries: &[RegistryEntry], q: &str) -> Vec<RegistryEntry> {
    let mut hits: Vec<RegistryEntry> = entries
        .iter()
        .filter(|e| {
            e.slug.to_ascii_lowercase().contains(q)
                || e.name.to_ascii_lowercase().contains(q)
                || e.description.to_ascii_lowercase().contains(q)
        })
        .cloned()
        .collect();
    hits.sort_by(|a, b| a.slug.cmp(&b.slug));
    hits
}

/// `None` = nothing matched anywhere — still exit 0, like single-source era.
async fn search_cmd(
    ctx: &Ctx,
    pinned: Option<&RegistrySource>,
    query: &str,
) -> Result<Option<ResolutionReceipt>, VynmError> {
    let q = query.to_ascii_lowercase();
    let wants = |entries: &[RegistryEntry]| !matching_entries(entries, &q).is_empty();

    let (source_name, hits): (String, Vec<RegistryEntry>) = match pinned {
        Some(src) => {
            let entries = fetch_registry(src, false, &ctx.tmp_dir).await?;
            let hits = matching_entries(&entries, &q);
            if hits.is_empty() {
                println!("no matches for '{query}'");
                return Ok(None);
            }
            (src.name.clone(), hits)
        }
        None => {
            // bare query: ledger-origin lookup only fires when the query is
            // verbatim a slug; otherwise plain listed order applies
            let ledger = load_state(&ctx.tmp_dir);
            let origin = ledger.get(query).map(|e| e.source.as_str());
            let candidates = bare_slug_candidates(&ctx.sources, origin);
            match probe_sources(&candidates, &ctx.tmp_dir, wants).await? {
                ProbeOutcome::Found(src, entries) => {
                    let hits = matching_entries(&entries, &q);
                    if hits.is_empty() {
                        println!("no matches for '{query}'");
                        return Ok(None);
                    }
                    (src.name.clone(), hits)
                }
                ProbeOutcome::NoMatch(_) => {
                    println!("no matches for '{query}'");
                    return Ok(None);
                }
            }
        }
    };

    println!("resolved from {source_name}");
    println!("{:<24} {:<10} {:<10} NAME", "SLUG", "VERSION", "STATUS");
    for e in hits {
        let status = if e.is_revoked() { "revoked" } else { &e.status };
        println!("{:<24} {:<10} {:<10} {}", e.slug, e.version, status, e.name);
    }
    Ok(Some(ResolutionReceipt { source_name }))
}

/// `--source <name>` filters rows by their recorded ledger origin; the name
/// is validated against the configured list even when nothing is installed.
fn list_cmd(ctx: &Ctx, source: Option<&str>) -> Result<(), VynmError> {
    let want = source
        .map(|n| ctx.resolve_source(Some(n)).map(|_| n.to_string()))
        .transpose()?;
    let state = load_state(&ctx.tmp_dir);
    let rows: Vec<_> = state
        .entries
        .iter()
        .filter(|e| want.as_deref().is_none_or(|w| e.source == w))
        .collect();
    if rows.is_empty() {
        match &want {
            Some(w) => println!("no plugins installed from '{w}'"),
            None => println!("no plugins installed"),
        }
        return Ok(());
    }
    println!(
        "{:<24} {:<10} {:<12} {:<20} PATH",
        "SLUG", "VERSION", "SOURCE", "INSTALLED AT"
    );
    for e in rows {
        println!(
            "{:<24} {:<10} {:<12} {:<20} {}",
            e.slug,
            e.version,
            e.source,
            format_ts(e.installed_at),
            plugin_dir(&ctx.tmp_dir).join(&e.slug).display()
        );
    }
    Ok(())
}

fn remove_cmd(ctx: &Ctx, slug: &str) -> Result<(), VynmError> {
    uninstall(slug, &ctx.tmp_dir)?;
    let removed = remove_plugin_config(&ctx.plugins_dir, slug)?;
    if !removed {
        println!("   no drop-in found — nothing to clean there");
    }
    Ok(())
}

fn disable_cmd(ctx: &Ctx, slug: &str) -> Result<(), VynmError> {
    report_toggle(slug, disable_plugin_config(&ctx.plugins_dir, slug)?);
    Ok(())
}

fn enable_cmd(ctx: &Ctx, slug: &str) -> Result<(), VynmError> {
    report_toggle(slug, enable_plugin_config(&ctx.plugins_dir, slug)?);
    Ok(())
}

fn report_toggle(slug: &str, outcome: Toggle) {
    match outcome {
        Toggle::Toggled => println!("✓ {slug}: done"),
        Toggle::Already => println!("'{slug}' was already in the requested state"),
        Toggle::Missing => println!("no drop-in found for '{slug}'"),
    }
}

// ── V-14: maintainer crypto ────────────────────────────────────────────────

fn keygen_cmd(name: Option<&str>, out: Option<&Path>, force: bool) -> Result<(), VynmError> {
    let name = name.unwrap_or("vynm");
    crate::validate::validate_identifier(name, 64)?;
    let path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(format!("./{name}.key")));
    let key = crate::keygen::generate_signing_key()?;
    crate::keygen::write_seed_file(&path, key.as_bytes(), force)?;
    eprintln!(
        "secret seed written to {} — keep it private, NEVER commit it",
        path.display()
    );
    // bare hex on stdout so the operator can paste it straight into
    // `marketplace_public_key:`
    println!("{}", crate::keygen::public_key_hex(&key));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_cmd(
    key_path: Option<&Path>,
    slug: &str,
    version: &str,
    sha256: &str,
    status: &str,
    archive_url: &str,
    min: &str,
    max: &str,
    verify: bool,
    public_key: Option<&str>,
    signature: Option<&str>,
) -> Result<(), VynmError> {
    let entry =
        crate::sign::entry_from_fields(slug, version, sha256, status, archive_url, min, max);
    if verify {
        if let Some(p) = key_path {
            eprintln!(
                "note: secret key not needed for verification — '{}' unused",
                p.display()
            );
        }
        let sig = signature.expect("clap enforces --signature with --verify");
        let pk = public_key.expect("clap enforces --public-key with --verify");
        crate::sign::verify_signature(&entry, sig, pk)?;
        println!("✓ signature valid for {slug}@{version}");
        return Ok(());
    }
    let Some(key_path) = key_path else {
        return Err(VynmError::InvalidInput(
            "--key <file> is required for signing (verification mode does not need it)".into(),
        ));
    };
    let key = crate::sign::load_signing_key(key_path)?;
    println!("{}", crate::sign::sign_entry(&key, &entry));
    Ok(())
}

fn new_cmd(name: &str, force: bool) -> Result<(), VynmError> {
    crate::scaffold::scaffold(Path::new("."), name, force)?;
    eprintln!("scaffolded ./{name}/");
    println!("next steps:");
    println!("  cd {name}");
    println!("  cargo build");
    println!("  # package the archive, then sign the registry entry:");
    println!("  vynm keygen <name> && vynm sign --key <name>.key --slug {name} --version 0.0.1 \\");
    println!("    --sha256 <archive-sha256> --archive-url <url> --min 0.1.0");
    Ok(())
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
