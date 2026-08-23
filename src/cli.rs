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

/// Only the keys vynm consumes today (V-06 single-source era); full multi-
/// source parsing arrives with V-09. Unknown keys are ignored on purpose —
/// vynm must tolerate every future kernel config addition.
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
pub struct Ctx {
    pub plugins_dir: PathBuf,
    pub source: RegistrySource,
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
        let mut source = official_source();
        if let Some(url) = raw.registry_url {
            // back-compat single-key override maps onto the official entry
            source.url = url;
        }
        if let Some(key) = raw.marketplace_public_key {
            source.public_key = Some(key);
        }
        if let Some(ttl) = raw.registry_cache_ttl_secs {
            source.cache_ttl_secs = ttl;
        }
        Ok(Self {
            plugins_dir: resolve_plugins_dir(config_path, raw.plugins_dir.as_deref()),
            source,
            tmp_dir: scratch_base(),
        })
    }

    /// §6.5: `--source <name>` validates against the configured list — one
    /// name today; adding N sources changes this lookup only, not the CLI.
    pub fn resolve_source(&self, requested: Option<&str>) -> Result<RegistrySource, VynmError> {
        match requested {
            None => Ok(self.source.clone()),
            Some(name) if name == self.source.name => Ok(self.source.clone()),
            Some(other) => Err(VynmError::InvalidInput(format!(
                "unknown source '{other}' — configured sources: {}",
                self.source.name
            ))),
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
        /// Path to the hex-seed key file (from `vynm keygen`)
        #[arg(long)]
        key: PathBuf,
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
                key,
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
            let src = ctx.resolve_source(source.as_deref())?;
            install_cmd(&ctx, &src, slug).await
        }
        Command::Search { query, source } => {
            let src = ctx.resolve_source(source.as_deref())?;
            search_cmd(&ctx, &src, query).await
        }
        Command::List { .. } => list_cmd(&ctx),
        Command::Remove { slug } => remove_cmd(&ctx, slug),
        Command::Enable { slug } => enable_cmd(&ctx, slug),
        Command::Disable { slug } => disable_cmd(&ctx, slug),
        // all handled above, before Ctx::load
        Command::Keygen { .. } | Command::Sign { .. } | Command::New { .. } => Ok(()),
    }
}

async fn install_cmd(ctx: &Ctx, src: &RegistrySource, target: &str) -> Result<(), VynmError> {
    let entries: Vec<RegistryEntry> = fetch_registry(src, false, &ctx.tmp_dir).await?;
    let installed = install(
        &entries,
        target,
        src,
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
    Ok(())
}

async fn search_cmd(ctx: &Ctx, src: &RegistrySource, query: &str) -> Result<(), VynmError> {
    let entries: Vec<RegistryEntry> = fetch_registry(src, false, &ctx.tmp_dir).await?;

    let q = query.to_ascii_lowercase();
    let mut hits: Vec<&RegistryEntry> = entries
        .iter()
        .filter(|e| {
            e.slug.to_ascii_lowercase().contains(&q)
                || e.name.to_ascii_lowercase().contains(&q)
                || e.description.to_ascii_lowercase().contains(&q)
        })
        .collect();
    hits.sort_by(|a, b| a.slug.cmp(&b.slug));
    if hits.is_empty() {
        println!("no matches for '{query}'");
        return Ok(());
    }
    println!("{:<24} {:<10} {:<10} NAME", "SLUG", "VERSION", "STATUS");
    for e in hits {
        let status = if e.is_revoked() { "revoked" } else { &e.status };
        println!("{:<24} {:<10} {:<10} {}", e.slug, e.version, status, e.name);
    }
    Ok(())
}

fn list_cmd(ctx: &Ctx) -> Result<(), VynmError> {
    let state = load_state(&ctx.tmp_dir);
    if state.entries.is_empty() {
        println!("no plugins installed");
        return Ok(());
    }
    println!(
        "{:<24} {:<10} {:<12} {:<20} PATH",
        "SLUG", "VERSION", "SOURCE", "INSTALLED AT"
    );
    for e in &state.entries {
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
    key_path: &Path,
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
        let sig = signature.expect("clap enforces --signature with --verify");
        let pk = public_key.expect("clap enforces --public-key with --verify");
        crate::sign::verify_signature(&entry, sig, pk)?;
        println!("✓ signature valid for {slug}@{version}");
        return Ok(());
    }
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
