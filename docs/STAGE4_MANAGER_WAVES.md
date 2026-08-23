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

- `vynm package <dir>` orchestration (zip+checksum+sign+upsert) replacing
  package.sh entirely — backlog under V-14.
- Remote signed templates via R2 — revisit post-Phase-B.
- Manager publish to crates.io still pending owner credentials.
