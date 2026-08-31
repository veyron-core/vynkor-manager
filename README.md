# vynkor-manager

[![crates.io](https://img.shields.io/crates/v/vynkor-manager.svg)](https://crates.io/crates/vynkor-manager)
[![CI](https://github.com/vynkor-core/vynkor-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/vynkor-core/vynkor-manager/actions/workflows/ci.yml)

Plugin marketplace manager for [vynkor](https://github.com/vynkor-core/vynkor).
The binary is **`vynm`**: it installs, updates, and manages kernel plugins from
registries.

## Install

```bash
cargo install vynkor-manager   # provides `vynm`
```

On first use vynm creates `~/.config/vyn/config.yaml` with the official
plugin registry pre-filled and every field documented inline — that file is
the single place where download sources live; edit it to repoint or add
sources. `vynm init [--force]` writes/regenerates the same starter config on
demand.

## What's inside

- `state` — `installed.json` ledger (`~/.local/share/vyn/` or
  `$VYNM_STATE_DIR`): one record per installed plugin with version, sha256,
  origin source, tree digest, and the version an install replaced (rollback).
  Older ledgers read back with per-field defaults, never errors.
- `dropin` — per-plugin auto-spawn drop-ins for the kernel
  (`<plugins.d>/<slug>.yaml`): write via `create_new` (O_EXCL — never follows
  a planted symlink), remove, disable/enable by rename (`.yaml.disabled`), and
  uninstall (dir + ledger record). Non-linux targets omit the `sandbox:` key,
  which only the linux kernel honors.
- `validate` — shared slug/plugin-id shape gate: non-empty ASCII
  `[A-Za-z0-9._-]`, bounded length, no bare path components.
- `package` — turn a built plugin directory into the distribution artifacts:
  release zip + `-src.zip`, `checksum.sha256`, Ed25519 `signature.sig`, the
  `dist/<slug>/versions/<version>/` layout, `latest.json`, and a v2
  `registry.json` upsert.
- `rollback` / `bundle` — restore the previous installed version kept by the
  last update, and move plugins between machines as one offline archive.

Env overrides follow the manager namespace: `VYNM_STATE_DIR`,
`VYNM_PLUGIN_DIR`.

## Dependency direction

`vynkor-manager` never depends on the kernel crate; both depend on
[`vynkor-wire`](https://github.com/vynkor-core/vynkor-wire) for shared types
(manifest parsing/validation included). The kernel has no runtime awareness of
vynm — drop-ins are just files.

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
vynm rollback <slug>
vynm remove|enable|disable <slug>
vynm bundle export [slugs...] [--out F] [--force]
vynm bundle import <archive> [--force]
vynm cache clean
vynm keygen|sign|new          # maintainer tooling
vynm package <dir> --name N --description D [--key F] ...   # see --help
vynm completions <bash|zsh|fish>
```

`<target>` is `[<source>/]<slug>[@<version>]`. Archives bypass registries:
a path (`./x.zip`) or direct URL installs without a signature/sha256-channel
guarantee. `--dry-run` resolves and prints the plan (permissions included)
but writes nothing. `bundle` moves installed plugins to air-gapped machines;
import verifies every tree digest against the bundled ledger before
committing anything.

### Exit codes — scripting contract

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
