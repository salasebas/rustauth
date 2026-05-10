# Initial Core Port Implementation Plan

> **For agentic workers:** Implement this plan task by task. Preserve Better Auth behavior where it matters, but design the Rust API around Rust conventions, type safety, explicit errors, and secure server-side boundaries.

**Goal:** Establish the first Rust-native OpenAuth core structure, DB schema contracts, and placeholder OAuth/social-provider module layout.

**Architecture:** `openauth-core` owns server-first contracts: models, schema metadata, database naming, options, errors, context, plugins, and utilities. `openauth-oauth` owns OAuth/OIDC and social providers, with placeholder modules only in this phase.

**Tech Stack:** Rust 2021, Cargo workspace, `serde`, `time`, `thiserror`, `indexmap`.

---

## Summary

Port the Better Auth core as a Rust-native foundation. Better Auth 1.6.9 is the behavioral reference, not a file-by-file template. This pass creates the real structure and contracts, while leaving OAuth2 and social providers without flow logic.

Default database naming must follow SQL conventions:

```text
users
accounts
sessions
verifications
rate_limits
```

Default column names must be plural-table-friendly and `snake_case`, including:

```text
id
created_at
updated_at
email_verified
user_id
provider_id
account_id
access_token
refresh_token
id_token
access_token_expires_at
refresh_token_expires_at
ip_address
user_agent
expires_at
last_request
```

## Key Changes

- Create `openauth-core` modules for `db`, `error`, `context`, `plugin`, `options`, `utils`, and `env`.
- Define base models: `User`, `Account`, `Session`, `Verification`, and `RateLimit`.
- Define typed DB metadata: `DbFieldType`, `DbField`, `DbTable`, `DbSchema`, `ForeignKey`, and `OnDelete`.
- Implement `auth_schema(options)` as the Rust equivalent of Better Auth's `getAuthTables`, with Rust/SQL defaults.
- Support explicit table and field name overrides through typed option structs.
- Add `thiserror`-based error types. Production code must not use `unwrap()` or `expect()`.
- Create placeholder structure in `openauth-oauth`:
  - `src/oauth2/mod.rs`
  - placeholder files for provider contracts, token handling, authorization URL, refresh, validation, and verification
  - `src/social_providers/mod.rs`
  - one provider module per Better Auth upstream provider, using Rust module names such as `microsoft_entra_id`

## Test Plan

- Add tests adapted from Better Auth DB behavior:
  - default table names are plural
  - default field names are `snake_case`
  - `refresh_token_expires_at` override does not reuse `access_token_expires_at`
  - custom verification fields are merged
  - `verifications` is excluded when secondary storage is configured
  - `verifications` is included when explicitly stored in database
  - `rate_limits` is included only when rate limit storage is database
- Add compile-time module structure tests for `openauth-oauth`.
- Run:

```bash
cargo test -p openauth-core
cargo test -p openauth-oauth
cargo clippy --all-targets --all-features --locked -- -D warnings
```

## Assumptions

- OpenAuth follows Better Auth's observable server behavior, not its TypeScript API shape.
- `openauth-oauth` remains the OAuth/OIDC crate; no new `openauth-oauth2` crate is introduced in this pass.
- OAuth2 and social providers are structure-only placeholders in this phase.
- Public APIs stay intentionally small until behavior and tests justify expanding them.
