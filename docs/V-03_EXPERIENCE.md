# V-03 implementation notes — vynkor-manager scaffold, state, drop-in writer

Task: **V-03** from the kernel's `docs/VYNM_ROADMAP.md` (manager lane, stage 2).
Repo born at extraction: `veyron-core/vynkor-manager`, binary `vynm`, lib
`vynkor_manager`, default branch `develop`. Implemented 2026-08-22.

## What changed

| File | Content |
|---|---|
| `src/state.rs` | Port of kernel `marketplace/state.rs` (154 L) verbatim + §6.2/§6.6 seams. |
| `src/dropin.rs` | Drop-in surface extracted from kernel `installer.rs`: `write_plugin_config` / `remove_plugin_config` / `disable_plugin_config` / `enable_plugin_config` / `uninstall` + `plugin_dir()`. |
| `src/validate.rs` | `validate_identifier` ported verbatim from kernel `utils/validate.rs` (MA-17 shape gate — security boundary). |
| `src/error.rs` | `VynmError` via thiserror; variant set mirrors the kernel slice the ports need. |
| `tests/state.rs`, `tests/dropin.rs` | Kernel `test_state.rs` ported (minus `skip_reinstall` cases → V-05) + drop-in security tests ported from `test_installer.rs` + new back-compat cases. |
| `.github/workflows/ci.yml` | Mirrors kernel gates + the no-kernel-dep assertion (`cargo tree -i veyron` must fail = empty inverted tree). |

## Seams applied (per plan §6.2 / §6.4 / §6.6)

1. **§6.2 ledger v2:** `InstalledEntry.source: String` next to `source_url`;
   `InstalledState.schema_version` (`LEDGER_SCHEMA_VERSION = 2`). Back-compat:
   pre-v2 files read with `source → "official"` (serde field default), version
   normalized in memory so the next save persists v2. `save_state` stamps the
   current version on every write — callers can't persist a stale schema.
   Updates/reinstalls resolving against the origin source is V-04/V-05
   behavior; the data model is ready here.
2. **§6.4 plain params:** `write_plugin_config(plugins_dir, &DropinParams)`
   takes a caller-supplied struct instead of `InstalledPlugin`. `sandbox`
   moved into params (D3 kills the hardcoded `plugin_id != "network"` hack in
   V-05's pipeline port; extracting now with the hack baked in would embed it
   in the new repo). Drop-in template line now says `vynm install`.
3. **§6.6 pub path helpers:** `state_dir()`, `state_path()` pub — stage-3
   config layering must not fork path logic.

## Deliberate deviations from the kernel original

- **Env namespace:** `VEYRON_STATE_DIR`/`VEYRON_PLUGIN_DIR` →
  `VYNM_STATE_DIR`/`VYNM_PLUGIN_DIR` per the rename policy (new code uses
  vynkor names). Default paths stay byte-identical to the kernel's
  (`~/.local/share/veyron/`, `~/.local/lib/veyron/plugins`) — vynm manages
  the same tree the kernel spawns from.
- **Error type:** hand-rolled `VeyronError` → thiserror `VynmError`. New repo,
  born modern; variant set kept kernel-shaped so future ports are mechanical.
- **`uninstall` keeps its `println!`s** for now (verbatim port); proper CLI
  messaging arrives with V-06.

## Gotchas

- First test run failed on my own new back-compat test: `InstalledState::default()`
  yields `schema_version: 0` and `save_state` persisted it as-is. Fix was the
  stamp-in-save_state design above, not a test tweak — the invariant lives at
  the write choke point.
- Integration-test binaries run as separate processes, but within one file
  tests run in parallel — env-var tests must all go through `temp_env`
  (`VYNM_STATE_DIR`/`VYNM_PLUGIN_DIR` closures), same pattern as the kernel.
- Repo bootstrap vs feature split: `develop` starts with an intentionally
  minimal bootstrap commit (.gitignore/LICENSE/readme stub) so V-03 has a
  base to PR against; the repo did not exist before this task.

## Gates (all green)

| Gate | Result |
|---|---|
| `cargo test --all-features` | ✓ 31 passed (16 dropin + 15 state) |
| `cargo tree -i veyron` empty | ✓ (CI asserts it permanently) |
| `cargo clippy --all-targets --all-features -- -D warnings` | ✓ clean |
| `cargo fmt --check` | ✓ |

## Follow-ups

1. **V-04**: registry client port + `RegistrySource` seam; cache path scheme
   `registry-cache/<name-or-urlhash>.json`; unsigned-gating matrix (§7.3).
2. **V-05**: install pipeline port (+ D2/D3 deletions during the port) —
   brings `skip_reinstall` and the manifest-validation call over
   `veyron_wire::manifest::validate_manifest` with `default_resolver`.
3. Ledger `source_url` for installs made by the kernel-era tooling says
   `https://...` while `source` defaults `"official"` — consistent enough;
   real multi-source resolution lands with V-04/V-09.
