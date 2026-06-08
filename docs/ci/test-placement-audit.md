# Test Placement Audit

**Date:** 2026-06-08  
**Scope:** 21 crates under `crates/` + `examples/full-app`  
**Policy:** [AGENTS.md](../../AGENTS.md) § Test placement

## Recommendation

**Leave the layout as-is; apply only minimal hygiene.**

~440 files under `tests/` are **integration-fast by design** (HTTP + `AuthRouter` + `MemoryAdapter`). They belong in `tests/` even when they finish in milliseconds after fast password fixtures. Speed is controlled by fixtures and CI lanes, not by moving files to `src/`.

Do **not** bulk-move `openauth-core/tests/api/routes/*` or `openauth-plugins/tests/*` into `src/` — high churn, no coverage gain.

### Do now (done or trivial)

| Action | Status |
| --- | --- |
| Remove duplicate `openauth-redis/tests/config.rs` (covered in `src/lib.rs`) | done |
| Document placement rules and per-crate classification | this file |

### Do on touch (optional)

Move pure unit tests into `#[cfg(test)]` next to the code when you already edit that module:

- `openauth-plugins/tests/username/validation.rs`
- `openauth-tokio-postgres/tests/driver.rs`
- `openauth-core/tests/crypto/buffer.rs`
- `openauth-stripe/tests/stripe_api/form_encoding.rs`
- `openauth-oidc/tests/flow.rs`

### Defer

- Centralizing per-crate `AuthRouter` harnesses into `test_utils` (large API design).
- Moving `openauth-core/tests/crypto/*` and `utils/*` (stable, fast in integration binary).

## Rules (quick reference)

| Location | Use for | Speed |
| --- | --- | --- |
| `src/` + `#[cfg(test)]` | One module, private API, pure logic | Usually fast |
| `crate/tests/` | Public API, router, adapters, cross-module wiring | Fast **or** slow |
| `#[ignore]` in `tests/` | Docker / live services | Integration workflow |
| `examples/*/tests/` | Full app e2e | Integration workflow |

**Misconception:** `tests/` ≠ “solo lentos”. `src/` ≠ “solo rápidos”.

## Per-crate summary

| Crate | `tests/` files | `src/` unit modules | Dominant `tests/` kind |
| --- | ---: | ---: | --- |
| `openauth-core` | 80 | 4 | integration-fast (routes, db, crypto via router) |
| `openauth-plugins` | 115 | 2 | integration-fast |
| `openauth-sso` | 70 | 2 | integration-fast (+ mock OIDC) |
| `openauth-scim` | 34 | 0 | integration-fast + docker adapters |
| `openauth-stripe` | 35 | 0 | integration-fast |
| `openauth-social-providers` | 35 | 6 | contract per provider |
| `openauth-axum` | 15 | 1 | integration-fast |
| `openauth-passkey` | 13 | 1 | integration-fast + `#[ignore]` SQL |
| `openauth-oauth-provider` | 8 | 0 | integration-fast |
| `openauth-cli` | 9 | 2 | CLI + snapshots + `#[ignore]` DB |
| `openauth-sqlx` | 4 | 0 | sqlite fast / postgres mysql Integration |
| `openauth` | 4 | 0 | public API + `#[ignore]` DB |
| `openauth-oauth` | 2 | 2 | integration-fast |
| `openauth-redis` | 1 | 3 | integration-docker (`redis_rate_limit.rs`) |
| `openauth-fred` | 2 | 2 | integration-docker |
| `openauth-telemetry` | 2 | 5 | integration + detectors in `src/` |
| `openauth-i18n` | 2 | 4 | integration-fast |
| `openauth-tokio-postgres` | 2 | 0 | adapter + driver unit-like |
| `openauth-deadpool-postgres` | 1 | 1 | integration-docker |
| `openauth-oidc` | 1 | 1 | unit-like + `src/discovery.rs` tests |
| `openauth-saml` | 1 | 1 | crypto/XML unit-like |
| `openauth-example-full-app` | 1 (`smoke.rs`) | 1 (`lib.rs` mod tests) | e2e + internal wiring |

## Clear misplacements

### Fixed

- **`openauth-redis/tests/config.rs`** — duplicate of `normalize_redis_url` tests in `src/lib.rs`; removed.

### Intentional exceptions

- **`examples/full-app/src/lib.rs` (`mod tests`)** — ~14 tests call private helpers (`build_auth`, `build_profile_auth`, `table_rows_for_db`, `ProfileCache`, etc.). `tests/smoke.rs` covers public HTTP e2e; `lib.rs` tests are **white-box integration** and stay in `src/` unless we expose a large `pub(crate)` test surface (not worth it).

### Optional future moves (low priority)

| File | Why move to `src/` |
| --- | --- |
| `openauth-plugins/tests/username/validation.rs` | Only `UsernameOptions::validate_username` |
| `openauth-tokio-postgres/tests/driver.rs` | Pure `postgres_params` / `param_refs` |
| `openauth-core/tests/crypto/buffer.rs` | `constant_time_equal` only |
| `openauth-stripe/tests/stripe_api/form_encoding.rs` | Pure `encode_form` |
| `openauth-oidc/tests/flow.rs` | URL helpers; overlaps `src/discovery.rs` |
| `openauth-sso/tests/sso/endpoints/saml/constants.rs` | Constant parity only |

## Docker / Integration lane (`#[ignore]`)

| File | Services |
| --- | --- |
| `openauth-plugins/tests/integration_matrix/mod.rs` | postgres, mysql, redis, valkey |
| `openauth-passkey/tests/passkey/sql.rs` | postgres, mysql |
| `openauth-cli/tests/db.rs` | postgres, mysql |
| `openauth/tests/public_api.rs` | postgres, mysql |

## Helper duplication

Shared password/router defaults: `openauth_core::test_utils` (good).

Still duplicated per crate (acceptable for now):

- Router builders: `openauth-axum/tests/common`, `openauth-plugins/tests/*/helpers.rs`, `openauth-sso/tests/sso/support.rs`, `openauth-passkey/tests/passkey/support.rs`, etc.
- `openauth-i18n/tests/common/mod.rs` — custom `RouteAdapter` (~500 LOC).

Consolidation is a **separate** design task (`test_utils::memory_router()` or similar).

## Verification

```bash
# Fast integration (typical crate)
cargo nextest run -p openauth-plugins --all-features

# Placement is correct if this still passes after moving unit tests only
cargo nextest run -p openauth-redis --all-features
```
