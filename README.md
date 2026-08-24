# vynkor-manager

Plugin marketplace manager for [Veyron](https://github.com/vynkor-core/vynkor)
(vynkor ecosystem). The binary is **`vynm`**: it installs, updates, and manages
kernel plugins from registries — the extraction of the kernel's marketplace
subsystem into a standalone tool (F1 / DC-1, see `docs/VYNM_ROADMAP.md` in the
kernel repo).

## What's inside (V-03 scaffold)

- `state` — `installed.json` ledger (`~/.local/share/veyron/` or
  `$VYNM_STATE_DIR`): one record per installed plugin with version, sha256,
  origin source. Schema v2; pre-v2 kernel ledgers read back with
  `source: "official"`. Plus the dependency-free UTC timestamp formatter.
- `dropin` — per-plugin auto-spawn drop-ins for the kernel
  (`<plugins.d>/<slug>.yaml`, R10-01): write via `create_new` (O_EXCL — never
  follows a planted symlink), remove, disable/enable by rename
  (`.yaml.disabled`, R10-04), and uninstall (dir + ledger record).
- `validate` — shared slug/plugin-id shape gate (MA-17): non-empty ASCII
  `[A-Za-z0-9._-]`, bounded length, no bare path components.

Env overrides follow the manager namespace: `VYNM_STATE_DIR`,
`VYNM_PLUGIN_DIR` (kernel equivalents: `VEYRON_STATE_DIR`/`VEYRON_PLUGIN_DIR`).

## Dependency direction

`vynkor-manager` never depends on the `veyron` kernel crate (CI asserts
`cargo tree -i veyron` is empty); both depend on
[`vynkor-wire`](https://github.com/vynkor-core/vynkor-wire) for shared types.
The kernel has no runtime awareness of vynm — drop-ins are just files.

## CLI

`vynm` manages plugins across one or more configured registry sources:

```text
vynm install <target> [--source N] [-y] [--allow-unsigned] [--dry-run]
vynm search <query> [--source N] [--json]
vynm info <target> [--source N] [--json]
vynm list [--source N] [--json]
vynm outdated [--json]
vynm update [slug] [--force] [-y] [--dry-run]
vynm verify [slug]
vynm remove|enable|disable <slug>
vynm cache clean
vynm keygen|sign|new          # maintainer tooling (V-14/V-20)
vynm completions <bash|zsh|fish>
```

`<target>` is `[<source>/]<slug>[@<version>]`. Archives bypass registries:
a path (`./x.zip`) or direct URL installs without a signature/sha256-channel
guarantee (V-15). `--dry-run` resolves and prints the plan (permissions
included) but writes nothing.

### Exit codes — scripting contract (V-16)

The mapping is type-based, not message-based: security refusals carry the
`Verification` error class internally. This table is stable API for scripts:

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | generic failure (bad input, missing plugin, manifest invalid, …) |
| `2` | network error (registry fetch/download failed) |
| `3` | verification failure — signature mismatch, digest mismatch,
  revoked entry, malformed/zip-slip archive, tampered tree |

### Shell completion

Static scripts: `vynm completions bash > …` (likewise `zsh`, `fish`).
Dynamic slug completion is exposed as the hidden command `__complete-slugs`,
which serves the LOCAL registry caches first (instant, offline) and only
touches the network when no usable cache exists.

## Gates

Same as every vynkor repo: `cargo test`, `cargo clippy --all-targets -- -D
warnings`, `cargo fmt --check`.

## License

MIT
