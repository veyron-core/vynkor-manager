# V-04 implementation notes — registry client port + RegistrySource seam

Task: **V-04** from the kernel's `docs/VYNM_ROADMAP.md` (manager lane).
Branch `feat/v04-registry-source`. Implemented 2026-08-22.

## What changed

| File | Content |
|---|---|
| `src/source.rs` | NEW — §6.1 `RegistrySource { name, url, public_key, allow_unsigned, cache_ttl_secs, enabled }` + `official_source()` default entry. |
| `src/registry.rs` | Kernel `registry.rs` (665 L) ported with the seam: every fetch/verify function takes `&RegistrySource` instead of loose `(url, ttl, key)` tuples. |
| `src/registry_tests.rs` | Ported kernel `registry_tests.rs` (842 L) via the MA-16 `#[path]` module pattern + new §7.3/D8 suites. |
| `Cargo.toml` | reqwest 0.12 (`default-features = false`, json + rustls-tls), ed25519-dalek 2, url 2, sha2 0.10; dev-deps tokio/macros/rt + mockito. |
| `src/error.rs` | + `Network(String)` variant. |

## Seams & decisions

1. **§6.1 single-source construction:** today's config keys
   (`registry_url` / `marketplace_public_key` / `registry_cache_ttl_secs`)
   map onto exactly one `RegistrySource`; unset → `official_source()`.
   Multi-source parsing is V-09 and changes resolution logic only.
2. **D5:** the pinned maintainer key and official URL live ONLY inside
   `official_source()` — no other compiled-in URL/key exists in the crate
   (the old `DEFAULT_REGISTRY_URL` / `MAINTAINER_PUBLIC_KEY_HEX` constants are
   gone; grep-enforceable).
3. **No pinned-key fallback in `verify_entry_signature`:** kernel version took
   `Option<&str>` and silently fell back to the pinned key on `None`. Here the
   caller passes `source.public_key` and simply never reaches verification
   when it is `None` — an unsigned source can't accidentally "verify".
4. **§6.3 cache scheme from day one:** `<state_dir>/registry-cache/<stem>.json`
   where stem = filename-safe source name else sha256-derived url hash.
   Old flat `registry-cache.json` is simply not read anymore (different path)
   — a fresh fetch repopulates; no migration needed for a TTL cache.
5. **§7.3 unsigned gating:** pure decision fn (`unsigned_action`) pins the
   matrix in tests; runtime half (`enforce_unsigned_consent`) adds the TTY
   prompt ([y/N], default NO) and the knob-naming hard error. Consented
   unsigned content is served live but **never cached** — the cache keeps its
   verified-only invariant, so stale fallback can never serve unverified data.
6. **D8 https-only:** one gate fn used for both the registry URL (inside
   fetch) and archive URLs (`pub ensure_archive_url_allowed` — the V-05
   installer calls it post-signature-verification, pre-download). http://
   refused unless `allow_unsigned` on that source; error names the knob.

## Gotchas

- **MSRV vs kernel drift:** clippy `-D warnings` caught
  `usize::is_multiple_of` (stable 1.87) in verbatim ported code — our
  rust-version is 1.85, the kernel's is newer. Replaced with `%`; comment left
  at the site so nobody "modernizes" it back.
- **mockito serves plain http://** — every network test's source needs
  `allow_unsigned: true` to pass the new transport gate before reaching
  signature logic; dedicated tests cover the refusal branches explicitly.
- `temp-env` 0.3 has no async helper — dropped a redundant smoke test instead
  of hand-rolling a runtime (path resolution already unit-covered).

## Test count: 67 (36 registry incl. ported security vectors, 16 dropin,
15 state)

## Follow-ups

1. **V-05**: install pipeline port calls `ensure_archive_url_allowed` +
   `resolve_relative_archive_urls` + wire `validate_manifest`; D2/D3 deletions
   happen during that port.
2. **V-09**: multi-source config parsing feeds a list of `RegistrySource`s;
   ledger `source` (V-03) drives origin enforcement.
