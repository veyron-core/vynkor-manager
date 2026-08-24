# V-16 implementation notes — CLI polish package

Task: **V-16** from the kernel's `docs/VYNM_ROADMAP.md` (manager lane — this
closes stage 3's last code item). Branch `feat/v16-cli-polish`, PR #20,
shipped in **0.4.0** (2026-08-24). V-10 needed nothing here — it had already
been merged earlier (`feat/v10-permission-preview`); only its roadmap checkbox
was stale.

## What shipped

| Item | Content |
|---|---|
| `vynm info <target>` | Full entry details (description, versions, permissions, sha256, archive_url, kernel bounds, signature presence). Grammar `[<source>/]<slug>[@<version>]`, resolution reuses the install path (origin-first probe / pinned single-source). Unpinned = highest non-revoked semver (mirrors update's picker), document-order fallback. |
| `--json` | search/list/info/outdated. Search no-match emits `{"resolved_from": null, "results": []}` so scripts never special-case an empty body. |
| `--source` column | search table joins list in showing where rows came from. |
| `--dry-run` | install: resolve + plan with permissions from the REGISTRY DOCUMENT (archive mode digests local files, never fetches URLs); update: batch plan, applies nothing. |
| `vynm cache clean` | Deletes `<state_dir>/registry-cache/*`; ledger untouched; idempotent on missing dir. Layout single-sourced via `registry::registry_cache_dir`. |
| completions | `vynm completions bash\|zsh\|fish` generated from the live clap surface (+`clap_complete`). Hidden `__complete-slugs` serves LOCAL caches first (TTL ignored), network only when no usable cache exists anywhere. |
| exit codes | Finalized TYPE-based: security refusals raise the new `VynmError::Verification` variant → exit 3 by variant; the message-sniffing heuristic in `cli::exit_code()` is gone. Message texts stay verbatim. |

## Decisions / lessons

1. **Keep the V-06 promise, not the hack.** V-06's notes said exit-code
   string-matching was honest *for then* and "if V-16 wants structured
   variants, only `exit_code()` changes". That under-promised: converting the
   raise sites (registry signature ×3, revocation, digest, zip-slip class ×6,
   verify summary) was mechanical but touched five files — the variant should
   have existed from day one. Message TEXTS stayed byte-identical throughout,
   which is what made the swap invisible.
2. **Pin deliberate non-changes.** Manifest-validation and corrupt-zip
   refusals were never part of the old verification sniffing, so they stay
   exit 1 — now asserted by name in tests/cli.rs, so nobody "fixes" them into
   breaking scripts later.
3. **Dry-run honesty rule:** the plan must show exactly what `install()`
   would pick (first slug/id match — `resolve_pinned` already narrows pins),
   and it must not fetch bytes, so per-action manifest requirements are
   absent by design; document-level permissions are printed instead.
4. **Render as pure builders.** All human/JSON output goes through pure
   `render_*` functions returning String — JSON shapes are unit-tested
   without mockito servers or stdout scraping.
5. **Smoke-test discovery:** a configured source literally named `local`
   collides with the reserved ledger marker — origin enforcement then treats
   those installs as archive-mode ("never updates"). Not fixed (renaming a
   source is free for operators), but worth remembering when debugging
   "everything up to date".

## Verification record

197 tests green (+8 new), clippy `-D warnings`, fmt clean; CI green before
merge. E2E smoke against a local HTTP registry covered search/info/--json/
--dry-run (registry + archive)/cache clean/completions/`__complete-slugs`;
ledger and plugin dirs verified untouched after every dry-run.
