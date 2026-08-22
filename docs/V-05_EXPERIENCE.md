# V-05 implementation notes — install pipeline port (+ D2/D3 deletions)

Task: **V-05** from the kernel's `docs/VYNM_ROADMAP.md` (manager lane).
Branch `feat/v05-installer-port`. Implemented 2026-08-22. This task spanned
three repos: two tiny wire releases first (prerequisites), then the port.

## Prerequisite wire cycles (shipped first)

1. **wire 0.2.5** (`PR veyron-wire#7`): `InstallManifest.sandbox: Option<bool>`
   — D3 needs the plugin's own hint readable through the single shared
   manifest type; real plugin.json documents adopt the key separately.
   Also carried a repo-license move to dual MIT/Apache (repo owner's pending
   working-tree change; split into its own `chore(license)` commit).
2. **wire 0.2.6** (`PR veyron-wire#8` + kernel `PR #42`):
   `validate_manifest(path, kernel_ver: Option<&Version>, resolver)`.
   D2 says vynm must never guess the running kernel's version — so when no
   authoritative version is available (kernel unreachable), `None` skips the
   range check and leaves it to boot-time validation. The kernel loader passes
   `Some(&kernel_ver)` — unchanged behavior there.

## What changed in this repo

| File | Content |
|---|---|
| `src/installer.rs` | NEW — the 8-step atomic pipeline: resolve → revoke-gate → signature → download → sha256 digest → zip-slip-guarded extraction → bak/rename atomic swap → manifest validation → ledger record. |
| `tests/installer.rs` | NEW — 17 tests: security battery ported from kernel `test_installer.rs` (digest mismatch, zip-slip ×2, exec-bit restore, entry-cap, zip-bomb, signature-before-download with mockito `expect(0)`) + end-to-end installs against mockito archives signed by a deterministic test key + D2/D3 acceptance cases. |
| `Cargo.toml` | + `veyron-wire 0.2.6` (manifest feature), `zip 2` (deflate only), `indicatif`, `semver`. |

## The deletions, explicitly (D2/D3)

- **D3 — no plugin-id special case anywhere:** the kernel's
  `let sandbox = installed.plugin_id != "network"` is gone. Sandbox preference
  = `manifest.sandbox.unwrap_or(true)` surfaced as
  `InstalledPlugin.sandbox_hint`; the caller feeds it to `DropinParams`
  (drop-in writing stayed in `dropin.rs` since V-03). Verified by
  `install_flows_manifest_sandbox_false_through`.
- **D2 — no install-time compat gate:** the old step-2
  `check_kernel_compatibility(entry, own_version)` is deleted. Instead an
  advisory pre-flight probes `$VYNM_KERNEL_URL` (default `127.0.0.1:8080`)
  `/health` for the real version: reachable → range checked as a *warning*
  and used for the final manifest validation; unreachable → warn-only note
  ("compat enforced at kernel boot") and `validate_manifest(..., None, ...)`.
  Integrity enforcement untouched: revocation gate, signature (when key
  configured), mandatory sha256 digest, zip-slip guards, size caps.
  Verified by `install_has_no_compat_gate_against_unreachable_kernel`
  (min_kernel_version 99.0.0 still installs).

## Other decisions

- **`signed_message` went pub** — registry publishers need the exact canonical
  form; V-14's `vynm sign` will too. Tests sign entries at runtime with a
  deterministic ed25519 key instead of hardcoding vectors (vectors stay in
  registry_tests for the verifier side).
- **Unsigned sources (§7.3-consented):** install skips signature verification
  but keeps the digest mandatory — tested both ways.
- **Ledger record gains origin:** `InstalledEntry.source = source.name`,
  `source_url = source.url` (§6.2 data model paying off already).
- Kernel health route is `/health` (`Health.version`), not `/status` as the
  roadmap sketched — probed the real endpoint.

## Gotchas

- zip 2.x writer API: permissions are `.unix_permissions(n)`
  (ExtendedFileOptions), not `.unix_mode()` — read-side ZipFile keeps its own
  `unix_mode()` getter.
- Async tests can't use `temp_env::with_var` closures (sync). Replaced with a
  mutex-guarded `Sandbox` struct that sets/restores env vars via Drop —
  serializes parallel async tests without nesting await into sync closures.
- `Result::unwrap()` on `install()` requires `InstalledPlugin: Debug` — added
  a derive.
- The test archive's plugin.json must carry `kernel_compatibility_range` —
  it stays a required manifest field even though vynm may skip *checking* it.

## Test count: 84 total (17 installer, 36 registry, 16 dropin, 15 state)

## Follow-ups / manual acceptance items

1. Roadmap acceptance "database/secrets install and run against this kernel"
   needs the real registry + a running kernel — manual e2e, not automatable
   here yet (V-06 CLI wraps install for that workflow).
2. **V-06**: clap CLI (`install/search/list/remove/enable/disable`) composes
   `install()` + `write_plugin_config(sandbox_hint)` + `--source` flag.
3. **V-07**: after V-03…V-06, delete `src/marketplace/` from the kernel;
   loader comment marking the coexistence window goes away then.
