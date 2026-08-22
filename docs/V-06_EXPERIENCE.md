# V-06 implementation notes — vynm CLI

Task: **V-06** from the kernel's `docs/VYNM_ROADMAP.md` (manager lane — this
closes it; the join task V-07 can now cut the kernel marketplace).
Branch `feat/v06-cli`. Implemented 2026-08-22.

## What changed

| File | Content |
|---|---|
| `src/cli.rs` | NEW — clap surface (`install/search/list/remove/enable/disable`), `--source` validation (§6.5), exit-code contract, minimal kernel-config reader, `resolve_plugins_dir` port. |
| `src/main.rs` | Real entry point: parse → run → `eprintln!` + mapped exit code. |
| `tests/cli.rs` | NEW — 8 tests: exit-code matrix, source rejection listing configured names, plugins.d round-trip cases, config round-trip with a kernel-style yaml. |
| `Cargo.toml` | + clap 4 (derive), serde_yaml; tokio moved to main deps (`rt-multi-thread` for `#[tokio::main]`). |

## Decisions

1. **Exit codes as scripting contract** (final polish deferred to V-16):
   `0 ok / 1 failure / 2 network / 3 verification`. Classification maps
   `VynmError::Network` → 2 and recognizes verification-class failures by
   their canonical ported wording ("signature", "integrity check failed",
   "revoked by the maintainer", "Malformed archive", "path traversal") → 3;
   everything else → 1. String-matching is honest here because the ports
   deliberately kept kernel message texts byte-identical; if V-16 wants
   structured variants, only `exit_code()` changes.
2. **`--config <kernel config.yaml>`** is the single global knob: drop-ins
   derive from `<config dir>/plugins.d`, registry keys
   (`registry_url` / `marketplace_public_key` / `registry_cache_ttl_secs`)
   map onto the built-in official source (back-compat per plan §6.5/V-04).
   Missing file = pure defaults — vynm works before a kernel config exists.
3. **`resolve_plugins_dir` ported verbatim** (explicit key wins, else
   `<config dir>/plugins.d`) + round-trip tests here against the kernel's own
   test expectations (risk-table item closed on both sides).
4. **D3 payoff:** `install` composes `InstalledPlugin.sandbox_hint`
   (manifest's own hint) into `DropinParams` — no plugin-id special case in
   the CLI either.
5. **`--source` grammar from day one:** validated against the configured
   list (one name today). Unknown name → error printing "configured sources:
   …" so scripts get an actionable failure.
6. Install size caps are constants for now (512 MiB archive / 1 GiB extracted
   / 100k entries); operator-tunable knobs arrive with V-09 config layering.

## Gotchas

- Nested tokio runtime inside `#[tokio::main]` panics — search/list paths are
  plain async fns under `run()`, no runtime-in-runtime hacks.
- Shell pipelines hide binary exit codes (`vynm … | tail` reports tail's);
  smoke-test with redirections when asserting codes manually.
- clippy `print_literal`: table headers belong in the format string, not as
  trailing literal args.

## Test count: 92 total (8 cli, 17 installer, 36 registry, 16 dropin, 15 state)

Manual acceptance (roadmap): scratch-`$HOME` e2e ran locally — `list` on
empty ledger prints and exits 0; unknown `--source` exits 1 with the
configured-sources list; real-registry installs verified in the V-05 e2e
suite via mockito archives.

## Follow-ups

1. **V-07 (join)**: delete `src/marketplace/` from the kernel; `vyn plugin
   install/search/...` become delegation shims exec'ing `vynm`.
2. **V-09**: multi-source registries replace the single-source mapping here;
   `--source` lookup grows from one name to N without grammar changes.
