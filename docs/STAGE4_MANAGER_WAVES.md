# Stage-4 manager waves — implementation notes (keygen / sign / new)

Consolidated record of the V-14/V-20 implementation waves plus the
independent verification findings (2026-08-22). Complements the per-task
experience docs (V-03…V-06).

## What shipped

| Command | Key decisions |
|---|---|
| `vynm keygen` | OS RNG via `getrandom 0.2` (already in lockfile — zero new versions). Secret file created with `O_EXCL` + `0o600` from the FIRST open (no truncate-in-place race); `--force` removes+recreates. Format = bare 64-hex seed, byte-compatible with the `VEYRON_SIGNING_KEY_HEX` convention so package.sh interop survives. Optional positional `[name]` resolves the default key filename. |
| `vynm sign` | Entry-level S1 signing. The message is NEVER formatted locally: the command constructs a `RegistryEntry` and calls `registry::signed_message()` — single source of truth, pinned by a literal-string test. Defaults `--status stable`, `--max *`. `--verify --public-key --signature` reuses `verify_entry_signature`; tamper exits **3** (verification class, scripting contract). |
| `vynm new <name>` | Templates embedded via `include_str!` (`templates/new/*`) with a single `{{name}}` substitution — zero new deps, offline-first. Name gated by `validate_identifier`; refuses existing dir without `--force`. Acceptance test builds the scaffold against the PUBLISHED `vynkor-sdk` (network-dependent → `#[ignore]` for CI). |

## Lessons / patterns worth reusing

1. **Construct-the-domain-object, don't duplicate format strings.** Sign
   works by building the entry and calling the same fn the verifier uses;
   a literal-pin test catches accidental format drift.
2. **Secret-file hygiene:** `O_EXCL` from first open beats "write then
   chmod" (no window with wrong perms); `--force` = remove+recreate, never
   truncate.
3. **Acceptance tests that need crates.io**: run locally, mark `#[ignore]`
   with the reason in the attribute so CI stays hermetic.
4. **UX fix found by adversarial smoke-testing**: `--verify` originally
   demanded `--key` (the SECRET) — verification must work on machines
   without secrets. Fixed via `Option<PathBuf>` + warn-and-ignore when a
   secret is passed anyway. Rule of thumb: every subcommand should be
   runnable in its least-privileged mode.

## Verification record

Independent re-run confirmed: 111 tests green (+4 cli-level through
`cli::run`), clippy `-D warnings`, fmt clean; E2E roundtrip incl. tamper
exit-3; keyless verify on a machine with no secret present.

## Deferred / follow-ups

- ~~`vynm package <dir>` orchestration~~ → **shipped in wave 5 below.**
- Remote signed templates via R2 — revisit post-Phase-B.
- Manager publish to crates.io still pending owner credentials.

## Wave 5 — parked items + package + non-linux drop-ins (2026-08-26)

The stage-3 "parked" pair plus the V-14 packaging backlog item and the §10
open question, all executed on one branch (`feat/stage3-followups`, PR #23).

| Command / change | Key decisions |
|---|---|
| `vynm package <dir>` | Full package.sh parity for zip/checksum/sign/upsert: dist layout `dist/<slug>/versions/<ver>/`, `checksum.sha256` (two spaces), S1 `signature.sig`, v2 registry upsert with CANONICAL top-level key order (meta → revoked → slugs alphabetically; needs serde_json `preserve_order`), relative `archive_url`, `latest.json` by max semver, dependencies map from manifest `requires`. Signing optional like package.sh; self-verified against the derived pubkey; warn-only when the signing key ≠ pinned maintainer key. DEVIATIONS (deliberate): no `cargo build`; `-src.zip` generated only when Cargo.toml/src exist. |
| `rollback <slug>` | `commit_staged` now RENAMES the demoted tree to `<slug>.prev` instead of deleting it, and snapshots the demoted ledger record into a new flat `previous` field on `InstalledEntry` (additive optional, LEDGER_SCHEMA_VERSION stays 3). Rollback integrity-gates the `.prev` tree with `tree_digest` BEFORE any swap (mismatch = Verification, exit 3); the swap is SYMMETRIC — current ↔ previous swap both trees and ledger records, so running rollback twice toggles back. Exactly one hop, no history stack. Drop-in untouched (binary path stable). |
| `bundle export/import` | Export = one zip: filtered `installed.json` at root + `plugins/<slug>/**` with unix modes preserved. Import is TRANSACTIONAL: all trees staged under `<plugin_base>/.bundle-stage-<pid>`, every digest checked against the bundled ledger BEFORE anything commits; mismatch aborts the whole import (exit 3) and cleans staging. Ledger entries travel verbatim (`source`/`source_url`) so origin enforcement survives machine moves. Traversal guards on member names; same size caps as install. |
| Non-linux drop-ins | `write_plugin_config` routes through pure `render_dropin(params, include_sandbox)`; `include_sandbox = cfg!(target_os = "linux")`. Resolves plan §10 open question 2 — no more `sandbox:` keys the kernel ignores off-linux. Linux format byte-pinned by tests. |

## Lessons / patterns worth reusing (wave 5)

1. **Env-lock self-deadlock:** test sandboxes that set process env must never
   coexist in one thread — a second `Sandbox::new()` while holding the
   non-reentrant mutex deadlocks the whole suite (surfaced only at
   `--test-threads=8`). Chain sandboxes through scoped helpers instead.
2. **Modes are integrity:** tree_digest covers exec bits, so ANY archive
   path (install, bundle export AND import) must carry
   `unix_permissions()`/restore `unix_mode()`. The e2e caught bundle import
   silently downgrading 755→644 into a self-inflicted tamper refusal.
3. **Reserved names bite configs:** an operator source named `local`
   collides with the ledger marker and updates silently skip those plugins
   (documented V-16 note; hit again during e2e).
4. **serde_json key order is a contract** once humans diff registry.json —
   `preserve_order` + explicit meta/revoked/sorted-slugs rebuild keeps
   byte-stability against package.sh output.

## Verification record (wave 5)

223 tests green (+26 over 197), clippy `-D warnings`, fmt clean. Live
terminal e2e against a local http.server registry: keygen → package →
install → update across versions → rollback ×2 → bundle round-trip onto a
fresh machine → tampered-file verify exit 3 → tampered-bundle import commits
nothing (exit 3). CI green on PR #22.

## Deferred / follow-ups (after wave 5)

- Remote signed templates via R2 — post-Phase-B.
- Manager publish to crates.io — owner credentials.
- Optional `cargo build` orchestration inside `vynm package` — rejected for
  now; build stays in the plugins repo CI.
