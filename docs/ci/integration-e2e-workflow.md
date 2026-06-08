# Integration & E2E Workflow

Workflow file: [`.github/workflows/integration.yml`](../../.github/workflows/integration.yml)

This lane runs **after or alongside** fast [CI](./test-performance-roadmap.md) and covers anything that needs live services or explicitly ignored tests.

## When it runs

- `pull_request`
- `push` to `main`
- `merge_group`
- `workflow_dispatch` (manual re-run)

Concurrency group: `integration-${{ github.workflow }}-${{ github.ref }}` (cancel in progress).

## Environment

```yaml
OPENAUTH_TEST_POSTGRES_URL: postgres://user:password@localhost:5432/openauth
OPENAUTH_TEST_MYSQL_URL: mysql://user:password@localhost:3306/openauth
```

Services are started per matrix row via `./scripts/ensure-test-services.sh`.

## Matrix

| Package | Services | Command | Purpose |
| --- | --- | --- | --- |
| `openauth-plugins` | postgres mysql redis valkey | `--run-ignored only` | `integration_matrix` Docker smoke |
| `openauth-passkey` | postgres mysql | `--run-ignored only` | SQL adapter migration tests |
| `openauth-cli` | postgres mysql | `--run-ignored only` | DB migrate smoke |
| `openauth` | postgres mysql | `--run-ignored only` | postgres/mysql plugin migration + HTTP |
| `openauth-sqlx` | postgres mysql | `--all-features` | postgres/mysql/sqlite adapters |
| `openauth-deadpool-postgres` | postgres | default nextest | deadpool adapter |
| `openauth-tokio-postgres` | postgres | default nextest | tokio-postgres adapter |
| `openauth-scim` | postgres mysql | `--all-features --test-threads 1` + doctests | SCIM DB adapters; excludes duplicate `create_schema` smokes on shared DB (contract covered by sqlite test) |
| `openauth-fred` | redis valkey | `--all-features` | Fred secondary storage / rate limit |
| `openauth-redis` | redis valkey | `--all-features` | Redis rate limit store |
| `openauth-example-full-app` | redis valkey | `--all-features` | **E2E** example app smoke |

## E2E: `openauth-example-full-app`

- Package: `examples/full-app` (`openauth-example-full-app`)
- Tests: `examples/full-app/tests/smoke.rs` (+ unit tests in `src/lib.rs`)
- Exercises dynamic auth routes (`/api/example/auth/{db}/{rate}/...`), home page, database viewer, rate-limit settings.
- Debug builds use `apply_fast_password_defaults` in `build_auth` for faster sign-up/sign-in smoke.
- Redis/valkey services are started for Fred/hybrid rate-limit paths even when smoke tests use the in-memory profile.

## Ignored tests (`#[ignore]`)

Run only with `cargo nextest run --run-ignored only`:

| Crate | Ignore reason |
| --- | --- |
| `openauth-plugins` | `requires docker compose up -d postgres/mysql/redis valkey` |
| `openauth-passkey` | postgres/mysql SQL migrations |
| `openauth-cli` | postgres/mysql migrate |
| `openauth` | postgres/mysql public API migration flows |

Fast CI runs the same packages **without** `--run-ignored`, so ignored tests are skipped there by design.

## SCIM on shared Docker databases

Postgres/MySQL adapter tests in `openauth-scim` share one database per service from `docker compose`. Parallel `create_schema` calls on default table names collide. Mitigations:

1. `MYSQL_ADAPTER_TEST_LOCK` / `POSTGRES_ADAPTER_TEST_LOCK` for in-process serialization.
2. Integration job runs `--test-threads 1` and excludes `*schema_and_provider_store_work_when_configured` (sqlite in-memory test keeps provider-store contract coverage).
3. `run_migrations_*_when_configured` tests remain in Integration.

## Run history

| Run | Workflow | Result | Notes |
| --- | --- | --- | --- |
| `27171088989` | CI | success (~173s) | First fast split |
| `27171088982` | Integration | failure | SCIM shared-DB collision |
| `27171373075` | Integration | failure | Same class of SCIM collisions (workflow filter pending) |
| `27171536274` | Integration | **success (~156s)** | SCIM filter + `--test-threads 1`; e2e example-app green |

## Local parity

```bash
# Plugins integration matrix
./scripts/ensure-test-services.sh postgres mysql redis valkey
cargo nextest run -p openauth-plugins --all-features --run-ignored only

# E2E example app
./scripts/ensure-test-services.sh redis valkey
export OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@127.0.0.1:5432/openauth
export OPENAUTH_TEST_MYSQL_URL=mysql://user:password@127.0.0.1:3306/openauth
cargo nextest run -p openauth-example-full-app --all-features

docker compose down -v
```

## Branch protection

Configure both checks on `main`:

- **CI** — format, clippy, fast crate matrix
- **Integration** — Docker / e2e matrix

They are independent workflows; both should be required for merge if full coverage is mandatory on every PR.
