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
}

/// Dispatch a parsed invocation; errors bubble to main for exit-code mapping.
pub async fn run(cli: &Cli) -> Result<(), VynmError> {
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
