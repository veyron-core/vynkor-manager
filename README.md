# vynkor-manager

Plugin marketplace manager for [Veyron](https://github.com/veyron-core/vynkor)
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
[`veyron-wire`](https://github.com/veyron-core/vynkor-wire) for shared types.
The kernel has no runtime awareness of vynm — drop-ins are just files.

## CLI

The `vynm` command surface (`install/search/list/remove/enable/disable`) lands
in V-06; the current build is a scaffold binary.

## Gates

Same as every vynkor repo: `cargo test`, `cargo clippy --all-targets -- -D
warnings`, `cargo fmt --check`.

## License

MIT
