# SQLx Plugin-Aware Migrations Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden SQLx schema creation and migrations so plugin-aware `DbSchema` changes are applied additively for SQLite and Postgres.

**Architecture:** Keep the public adapter API unchanged. Each dialect inspects its own catalog, creates missing tables in schema order, adds missing columns to existing tables, and creates missing indexes after table/column work completes.

**Tech Stack:** Rust, SQLx, SQLite, Postgres, OpenAuth `DbSchema`.

---

### Task 1: Rebase Onto Local Main Without Merge Commit

**Files:** none

- [x] Confirm worktree status and current ref.
- [x] Rebase detached `HEAD` onto local `main` instead of creating a merge commit.
- [x] Continue only after the worktree is clean.

### Task 2: Add Regression Coverage

**Files:**
- Modify: `crates/openauth-sqlx/tests/sqlite_adapter.rs`
- Modify: `crates/openauth-sqlx/tests/postgres_adapter.rs`

- [x] Add SQLite regression test for adding an indexed plugin column to an existing core table.
- [x] Add SQLite regression test for creating plugin tables with indexes and foreign keys.
- [x] Add Postgres regression test for adding an indexed plugin column to an existing core table.
- [x] Add Postgres regression test for creating plugin tables with indexes and foreign keys.
- [x] Run the SQLite migration tests and confirm the existing-table plugin-column case fails before implementation.

### Task 3: Implement Additive Schema Diff

**Files:**
- Modify: `crates/openauth-sqlx/src/sqlite/schema.rs`
- Modify: `crates/openauth-sqlx/src/postgres/schema.rs`

- [x] For each dialect, detect whether a table exists before issuing `CREATE TABLE`.
- [x] For existing tables, inspect columns and issue `ALTER TABLE ... ADD COLUMN` only for missing fields.
- [x] Preserve existing `CREATE TABLE` behavior for missing tables, including column constraints.
- [x] Preserve post-table index creation and make reruns idempotent.

### Task 4: Verify

**Files:** none

- [x] Run `cargo fmt`.
- [x] Run `cargo test -p openauth-sqlx --features sqlite`.
- [x] Run `OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth cargo test -p openauth-sqlx --no-default-features --features postgres`.
- [x] Run `cargo test -p openauth-sqlx --all-features --no-run`.
- [x] Review the final diff for scope creep and unrelated changes.

### Task 5: Public API and Index Repair Follow-Up

**Files:**
- Modify: `crates/openauth/Cargo.toml`
- Modify: `crates/openauth/tests/public_api.rs`
- Modify: `crates/openauth-sqlx/tests/sqlite_adapter.rs`
- Modify: `crates/openauth-sqlx/tests/postgres_adapter.rs`

- [x] Add a SQLite public API test that goes through `OpenAuth::run_migrations()`, plugin schema, and HTTP auth routes.
- [x] Add a Postgres public API test that isolates with a dedicated PostgreSQL schema, goes through `OpenAuth::run_migrations()`, plugin schema, and HTTP auth routes.
- [x] Add SQLite regression coverage for recreating a missing index on an existing indexed plugin column.
- [x] Add Postgres regression coverage for recreating a missing index on an existing indexed plugin column.
- [x] Run focused SQLite and Postgres checks for the new tests.
- [x] Re-run `OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth cargo test -p openauth`.
- [x] Re-run `cargo test -p openauth-sqlx --features sqlite`.
- [x] Re-run `OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth cargo test -p openauth-sqlx --no-default-features --features postgres`.
- [x] Re-run `cargo test -p openauth-sqlx --all-features --no-run`.

### Task 6: SQLx Migration Planning Phase 1

**Files:**
- Add: `crates/openauth-sqlx/src/migration.rs`
- Modify: `crates/openauth-sqlx/src/lib.rs`
- Modify: `crates/openauth-sqlx/src/sqlite/mod.rs`
- Modify: `crates/openauth-sqlx/src/sqlite/schema.rs`
- Modify: `crates/openauth-sqlx/src/postgres/mod.rs`
- Modify: `crates/openauth-sqlx/src/postgres/schema.rs`
- Modify: `crates/openauth-sqlx/tests/sqlite_adapter.rs`
- Modify: `crates/openauth-sqlx/tests/postgres_adapter.rs`

- [x] Add public `openauth_sqlx::migration` types for migration plans, table creates, column adds, index creates, warnings, and statements.
- [x] Add concrete `plan_migrations()` and `compile_migrations()` methods on SQLite and Postgres adapters without changing `DbAdapter`.
- [x] Refactor SQLite schema creation to build an additive plan, execute ordered statements, and warn on existing column type mismatches.
- [x] Refactor Postgres schema creation to build an additive plan, execute ordered statements, and warn on existing column type mismatches.
- [x] Preserve additive-only behavior: create missing tables, add missing columns, create missing standalone indexes, and avoid drops/renames/type rewrites.
- [x] Keep MySQL behavior unchanged.
- [x] Add SQLite tests for stable `to_be_created`, plugin `to_be_added`, deferred indexes, no-op compile, and type mismatch warnings.
- [x] Add Postgres tests for stable `to_be_created`, plugin `to_be_added`, deferred indexes, no-op compile, and type mismatch warnings.
- [x] Run `cargo fmt --check`.
- [x] Run `cargo test -p openauth`.
- [x] Run `cargo test -p openauth-sqlx --features sqlite`.
- [x] Run `OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth cargo test -p openauth-sqlx --no-default-features --features postgres`.
- [x] Run `cargo test -p openauth-sqlx --all-features --no-run`.
- [x] Run `git diff --check`.

### Task 7: SQLx MySQL Migration Planning Phase 1

**Files:**
- Modify: `crates/openauth-sqlx/src/mysql/mod.rs`
- Modify: `crates/openauth-sqlx/src/mysql/schema.rs`
- Modify: `crates/openauth-sqlx/tests/mysql_adapter.rs`
- Modify: `crates/openauth/Cargo.toml`
- Modify: `crates/openauth/tests/public_api.rs`

- [x] Add concrete `plan_migrations()` and `compile_migrations()` methods on `MySqlAdapter` without changing `DbAdapter`.
- [x] Refactor MySQL schema creation to build an additive plan, execute ordered statements, and warn on existing column type mismatches.
- [x] Introspect MySQL tables, columns, and indexes through `information_schema` scoped to `DATABASE()`.
- [x] Preserve MySQL SQL conventions: InnoDB/utf8mb4 table creation, `ALTER TABLE ... ADD COLUMN`, and standalone `CREATE INDEX`.
- [x] Avoid MySQL destructive migrations: no drops, renames, type rewrites, `MODIFY COLUMN`, or `CHANGE COLUMN`.
- [x] Add MySQL tests for stable `to_be_created`, plugin `to_be_added`, deferred indexes, no-op compile, type mismatch warnings, missing index repair, and plugin table FK/index creation.
- [x] Add an OpenAuth public API test for MySQL `run_migrations()`, plugin schema, and HTTP auth flow.
- [x] Run `OPENAUTH_TEST_MYSQL_URL=mysql://user:password@localhost:3306/openauth cargo test -p openauth-sqlx --no-default-features --features mysql`.
- [x] Run `OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth OPENAUTH_TEST_MYSQL_URL=mysql://user:password@localhost:3306/openauth cargo test -p openauth`.

### Assumptions

- Scope is additive-safe only: no drops, renames, type rewrites, or destructive constraint migrations.
- MySQL follows the same additive-safe migration planning boundary as SQLite and Postgres.
- No new dependency is needed.
