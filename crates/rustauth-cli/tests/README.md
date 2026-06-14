# rustauth-cli integration tests

## Running

```bash
# Default CI surface (all features, skips Docker-only tests)
cargo nextest run -p rustauth-cli --all-features

# Migration-focused suite (SQLite, runs in CI)
cargo nextest run -p rustauth-cli --all-features --test migration_flows

# Non-migration CLI commands (doctor, info, init, plugins, schema, generate flags)
cargo nextest run -p rustauth-cli --all-features --test cli_commands

# Docker-backed Postgres adapter flows (ignored by default)
cargo nextest run -p rustauth-cli --all-features --test migration_flows --run-ignored all

# Legacy db.rs Docker cases
cargo nextest run -p rustauth-cli --all-features --test db --run-ignored all
```

Set `RUSTAUTH_CLI_TEST_POSTGRES_URL` when your Postgres is not
`postgres://user:password@localhost:5432/rustauth` (same as `./scripts/ensure-test-services.sh postgres`).

## Layout

| File | Focus |
| --- | --- |
| `cli_commands.rs` | Doctor, info, init/plugins errors, schema edge cases, generate flag validation, completions |
| `migration_flows.rs` | End-to-end CLI migration behavior (incremental plugins, errors, idempotence) |
| `db.rs` | CLI db commands, adapter matrix, generate/migrate wiring |
| `regression_gaps.rs` | Edge cases (dry-run, env, unsupported adapters, telemetry) |
| `schema_snapshots.rs` | Dialect SQL snapshots |
| `schema_registry_audit.rs` | Plugin ids in `rustauth.toml` vs CLI schema registry |
| `support/mod.rs` | Shared config helpers and SQLite/Postgres fixtures |

## Migration test matrix (`migration_flows.rs`)

| Test | What it proves |
| --- | --- |
| `sqlite_incremental_plugin_migration_adds_only_new_tables` | Core migrate → enable `api-key` → only `api_keys` → enable `jwt` → only `jwks` |
| `sqlite_incremental_multiple_table_plugins_in_one_pass` | Enabling several table plugins at once creates only missing tables |
| `sqlite_incremental_column_plugin_admin_adds_user_columns` | Column-only plugins add fields without recreating core tables |
| `sqlite_plugins_add_command_triggers_incremental_migrate` | `rustauth plugins add` + `db migrate` end-to-end |
| `sqlite_removed_plugin_from_toml_does_not_drop_tables` | Removing a plugin id is non-destructive (additive-only policy) |
| `sqlite_second_migrate_reports_no_changes` | Idempotent second `db migrate` |
| `sqlite_db_status_check_exits_nonzero_when_pending` | `db status --check` for CI gates |
| `sqlite_db_status_json_reports_pending_plan` | `--json` contract |
| `sqlite_migrate_rejects_incompatible_existing_table` | Type mismatch → warnings + blocked migrate |
| `sqlite_migrate_blocks_on_foreign_key_mismatch` | FK mismatch → unsafe plan guard |
| `sqlite_migrate_dry_run_reports_unsafe_plan_without_applying` | Unsafe plans fail before dry-run output |
| `sqlite_migrate_fails_when_adding_unique_column_to_existing_sqlite_table` | SQLite limitation when adding UNIQUE columns to populated tables |
| `sqlite_generate_after_full_migrate_is_up_to_date` | No duplicate SQL after schema matches DB |
| `sqlite_db_migrate_without_config_fails` | Missing `rustauth.toml` |
| `sqlite_db_migrate_without_database_url_fails` | Missing `DATABASE_URL` |
| `sqlite_db_migrate_passkey_without_cli_feature_reports_disabled` | Plugin/feature alignment |
| `postgres_incremental_plugin_migration_adds_only_new_tables` | Same incremental flow on sqlx/postgres (Docker, ignored) |
| `tokio_postgres_incremental_plugin_migration_adds_only_new_tables` | Incremental flow on `tokio-postgres` (Docker, ignored) |
| `deadpool_postgres_incremental_plugin_migration_adds_only_new_tables` | Incremental flow on `deadpool-postgres` (Docker, ignored) |

Manual playground: [`examples/cli-migrate-playground`](../../examples/cli-migrate-playground/README.md).

## Non-migration command matrix (`cli_commands.rs`)

| Test | What it proves |
| --- | --- |
| `doctor_warns_on_legacy_router_pattern` | `integration.legacy_router` finding in JSON |
| `doctor_warns_on_double_nest_pattern` | `integration.double_nest` finding in JSON |
| `doctor_reports_pending_schema_before_migrate` | `database.pending_schema` before first migrate |
| `doctor_reports_schema_up_to_date_after_migrate` | `database.schema` info after migrate; no pending |
| `doctor_production_requires_https_base_url` | `security.base_url_https` when `production = true` and HTTP base URL |
| `doctor_strict_fails_on_pending_schema` | `--strict` exits non-zero on pending schema |
| `info_human_output_lists_findings` | Human `info` output (not `--json`) |
| `init_rejects_unknown_plugin` | Unknown plugin id rejected at init |
| `plugins_add_rejects_unknown_plugin` | Unknown plugin id rejected by `plugins add` |
| `plugins_remove_is_idempotent_in_config` | Second `plugins remove` is a no-op in TOML |
| `plugins_remove_then_migrate_keeps_tables` | Removing plugin id does not drop migrated tables |
| `schema_print_rejects_unknown_dialect` | Unsupported `--dialect` error |
| `schema_print_json_honors_config_plugins` | Config `admin` plugin adds `role` to JSON schema |
| `db_generate_rejects_output_and_output_dir_together` | Mutually exclusive `--output` / `--output-dir` |
| `db_commands_fail_on_malformed_toml` | Parse error on invalid `rustauth.toml` |
| `completions_emits_zsh_script` | Zsh completion smoke |
| `completions_emits_fish_script` | Fish completion smoke |
