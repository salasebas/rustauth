# CI Test Performance Roadmap

## Goal

Keep OpenAuth CI fast without reducing coverage:

- **CI** (`.github/workflows/ci.yml`): deterministic fixture tests, no Docker services.
- **Integration** (`.github/workflows/integration.yml`): Docker-backed adapters, ignored matrix tests, and e2e (`openauth-example-full-app`).
- Real scrypt stays in `openauth-core` crypto tests; route/plugin fixtures use `openauth_core::test_utils::with_integration_test_defaults`.

## Workflow Split (2026-06-08)

| Workflow | Trigger | Gate job | Services |
| --- | --- | --- | --- |
| `CI` | PR / push `main` / merge group | `CI` | none |
| `Integration` | PR / push `main` / merge group / `workflow_dispatch` | `Integration` | postgres, mysql, redis, valkey per matrix row |

Shared helpers live in `crates/openauth-core/src/test_utils/fast_password.rs` (`test-utils` feature).

## CI Results — Run `27171088989` (push `6f26ea0b`)

Commit: `ci: split integration workflow and speed adapter test fixtures`

**Wall clock:** ~173s (previously ~19m29s on run `27120004789` for the monolithic workflow).

### Fast lane job wall times (includes compile + cache)

| Job | Wall | Nextest (when logged) | Notes |
| --- | ---: | --- | --- |
| `Test openauth` | 159s | 55 passed, 2 skipped (postgres/mysql ignored) | was 199s total |
| `Test openauth-sso` | 120s | — | no password fixtures |
| `Test openauth-plugins` | 108s | **733 passed, 3 skipped in 5.7s** | was **1157s** |
| `Test openauth-core` | 94s | **594 passed in 34.4s** | was **218s** |
| `Test openauth-passkey` | 86s | 94 passed, 2 skipped locally ~0.23s | was **224s** |
| `Test openauth-cli` | 83s | ignored DB tests → Integration |
| `Test openauth-sqlx` | 71s | **39 passed (sqlite only)** | postgres/mysql → Integration |
| `Test openauth-social-providers` | 71s | — | was 307s (mostly setup) |
| `Test openauth-oauth` | 27s | — | |

Crates removed from fast CI (moved to Integration): `openauth-deadpool-postgres`, `openauth-tokio-postgres`, `openauth-fred`, `openauth-redis`, `openauth-scim`, `openauth-example-full-app`.

### Local fast-lane reference (2026-06-08)

| Crate | Command | Result |
| --- | --- | --- |
| `openauth-core` | `cargo nextest run -p openauth-core --all-features` | 594 passed, ~14s |
| `openauth-plugins` | `cargo nextest run -p openauth-plugins --all-features` | 733 passed, 3 skipped, ~3.1s |
| `openauth-passkey` | `cargo nextest run -p openauth-passkey --all-features` | 94 passed, 2 skipped, ~0.23s |
| `openauth` | `cargo nextest run -p openauth --all-features` | 55 passed, 2 skipped, ~19s |
| `openauth-sqlx` | `cargo nextest run -p openauth-sqlx --features sqlite` | 39 passed, ~0.12s |

## Integration / E2E Results — Run `27171088982`

**Wall clock:** ~179s (matrix jobs in parallel).

| Job | Wall | Conclusion | Notes |
| --- | ---: | --- | --- |
| `Test openauth` | 169s | success | `--run-ignored only` (postgres/mysql migrations) |
| `Test openauth-plugins` | 148s | success | `--run-ignored only` (integration matrix) |
| `Test openauth-cli` | 134s | success | `--run-ignored only` (DB migrate smoke) |
| `Test openauth-scim` | 115s | **failure** | Shared DB `create_schema` collisions — workflow uses `--test-threads 1` + nextest filter |
| `Test openauth-passkey` | 108s | success | `--run-ignored only` (postgres/mysql SQL) |
| `Test openauth-sqlx` | 105s | success | `--all-features` + postgres/mysql |
| `Test openauth-example-full-app` | 102s | success | e2e smoke (`examples/full-app/tests/smoke.rs`) |
| `Test openauth-fred` | 83s | success | redis + valkey |
| `Test openauth-deadpool-postgres` | 64s | success | postgres |
| `Test openauth-tokio-postgres` | 64s | success | postgres |
| `Test openauth-redis` | 64s | success | redis + valkey |

Env vars set at workflow level: `OPENAUTH_TEST_POSTGRES_URL`, `OPENAUTH_TEST_MYSQL_URL`.

See also: [integration-e2e-workflow.md](./integration-e2e-workflow.md).

## Completed Changes

- Centralized fast password fixtures in `openauth-core::test_utils`.
- Applied `with_integration_test_defaults` across core, plugins, i18n, axum, sso, fred, passkey, sqlx, deadpool, tokio-postgres, scim, captcha, and example full-app (debug builds).
- Split GitHub Actions into fast `CI` and slow `Integration` workflows.
- Marked Docker-only tests with `#[ignore]` and run them via `--run-ignored only` in Integration.
- `openauth-example-full-app` runs in Integration (e2e), not fast CI.

## Crate Status

| Crate | Fast CI | Integration | Fixture status |
| --- | --- | --- | --- |
| `openauth-core` | yes | — | done; real scrypt in `tests/crypto/password.rs` |
| `openauth-plugins` | yes | ignored matrix | done |
| `openauth-passkey` | yes | ignored SQL | done |
| `openauth` | yes (sqlite) | postgres/mysql ignored | done |
| `openauth-sqlx` | sqlite only | full features | done |
| `openauth-deadpool-postgres` | — | yes | done |
| `openauth-tokio-postgres` | — | yes | done |
| `openauth-scim` | — | yes | done; MySQL lock added for CI |
| `openauth-fred` / `openauth-redis` | — | yes | fred fixtures done |
| `openauth-example-full-app` | — | e2e | fast password in debug |
| `openauth-cli` | yes | ignored DB | done |
| `openauth-oauth`, `openauth-saml`, `openauth-stripe`, `openauth-telemetry`, `openauth-social-providers` | yes | — | no action needed |

## Next Steps

1. Re-run Integration after MySQL SCIM lock fix; confirm `Integration` gate green.
2. Optionally add `workflow_dispatch` badge / required-check docs in branch protection for both workflows.
3. Monitor `Test openauth` and `Test openauth-sso` wall times (still dominated by compile, not nextest).

### Audit commands

```bash
gh run list --workflow CI --limit 5
gh run list --workflow Integration --limit 5
gh run view <RUN_ID> --json jobs --jq '.jobs[] | [.name, .conclusion, .startedAt, .completedAt] | @tsv'
gh run view <RUN_ID> --job <JOB_ID> --log | rg "Summary \\["
```

### Per-crate verification

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate> --all-features
```
