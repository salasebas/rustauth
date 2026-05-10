# Core Auth/API/Crypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the server-first OpenAuth core slice for API contracts, auth initialization, context, cookies, crypto, JWT, password hashing, random strings, secret rotation, and tests.

**Architecture:** `openauth-core` owns framework-neutral contracts and primitives. Concrete HTTP framework integrations, browser/client SDKs, and concrete database adapters stay out of scope.

**Route Architecture:** Core owns the route registry once, using OpenAuth endpoint metadata plus `http` request/response types. Framework crates such as a future `openauth-axum` should only mount a catch-all under the configured base path and translate framework requests into core requests; auth routes should not be reimplemented per framework.

**Tech Stack:** Rust 2021, Cargo workspace, `serde`, `serde_json`, `thiserror`, `time`, `tokio`, `http`, `base64`, `hex`, `rand`, `hmac`, `sha2`, `subtle`, `chacha20poly1305`, `scrypt`, `hkdf`, and `josekit`. JWT HS256 is implemented directly with `hmac`/`sha2`; JWE cookie-cache parity is implemented with Better Auth-compatible `dir` + `A256CBC-HS512` encryption and HKDF-SHA256 key derivation.

---

## Summary

Implement the next core/public-auth slice as a Rust-native port of Better Auth 1.6.9 behavior. Use upstream `packages/better-auth/src/{auth,api,context,cookies,crypto}` and `packages/core/src/{api,context,types}` as behavioral references, not as mechanical structure to copy.

## Key Changes

- Add public primitive/contract modules in `openauth-core`: `api`, `cookies`, and `crypto`.
- Add the product initializer in `crates/openauth`, mirroring Better Auth's package-level entrypoint while re-exporting core primitives.
- Expand `OpenAuthOptions` into typed configuration for secrets, base URL/path, sessions, cookies, password policy, rate limit, logger, and disabled paths.
- Replace placeholder `AuthContext` with runtime context containing resolved URL/path, session config, cookies, secret config, password functions, logger, adapter handle metadata, plugin metadata, and request-state integration.
- Keep API HTTP-agnostic with `http` crate request/response types plus OpenAuth-owned endpoint abstractions.
- Keep routing framework-neutral: core matches method/path once; framework adapters mount the configured base path and delegate to core.
- Provide `open_auth(options)` and `OpenAuth` from `crates/openauth` with handler, endpoint registry, options, and context access.

## Crypto And Secret Rotation

- [x] Add `crypto::buffer::constant_time_equal`.
- [x] Add `crypto::random::generate_random_string` with Better Auth charset `a-z`, `0-9`, `A-Z`, `-_`.
- [x] Add `crypto::password::{hash_password, verify_password}` using the Better Auth-compatible `salt:hash` scrypt format.
- [x] Add `crypto::jwt::{sign_jwt, verify_jwt}` for HS256 signed JWT.
- [x] Add symmetric encryption helpers and `$ba$<version>$<ciphertext>` envelope handling.
- [x] Add `SecretConfig`, parsing, validation, and build helpers.
- [x] Implement Better Auth-compatible JWE helpers for encrypted cookie-cache payloads.

## Cookies And Sessions

- [x] Add cookie types, secure/host prefixes, parser, serializer, and `Set-Cookie` parser.
- [x] Port default auth cookie names and attributes.
- [x] Implement session cookie helpers and chunked cookie store with cleanup.
- [x] Implement compact and JWT cookie cache signing with HMAC and version checks.
- [x] Leave concrete DB-backed session loading to existing adapter contracts.
- [x] Add DB-backed session lifecycle helpers over the adapter contracts.

## Core Auth Storage

- [x] Add DB-backed user lifecycle helpers over the adapter contracts.
- [x] Add DB-backed credential account helpers over the adapter contracts.
- [x] Add verification token lifecycle helpers for email verification, password reset, and OTP-style flows.
- [x] Add higher-level email/password sign-up and sign-in service methods over user/account/session stores.
- [x] Wire get-session/sign-out behavior to signed cookies, session store, user lookup, and cookie-cache refresh.
- [x] Add safe JSON/form request body parsing helpers for auth endpoints.
- [x] Add typed auth flow error codes for invalid credentials, duplicate users, missing session, email verification, and validation failures.

## API/Auth/Context

- [x] Add framework-neutral endpoint and middleware contracts in `openauth-core`.
- [x] Add package-level `open_auth` initializer in `crates/openauth`.
- [x] Add framework-neutral DB-backed auth route builders for `/sign-up/email`, `/sign-in/email`, `/get-session`, and `/sign-out`, organized under `api/routes/*` for upstream parity.
- [x] Return Better Auth-shaped `{ token, user }` bodies from email/password sign-up and sign-in routes while keeping `{ session, user }` for get-session.
- [x] Add a Better Auth-inspired `create_auth_endpoint` builder with endpoint options, per-endpoint middleware, allowed media types, body schema validation, operation IDs, and OpenAPI schema generation.
- [x] Expand OpenAPI generation toward upstream shape: operation metadata, default error responses, request body fallback for body-using methods, path parameter formatting, security schemes, top-level security, servers, tags, and model schemas.
- [x] Add DB-backed session route builders for `/list-sessions`, `/revoke-session`, `/revoke-sessions`, and `/revoke-other-sessions`.
- [x] Add DB-backed user/password route builders for `/update-user`, `/change-password`, `/set-password`, `/verify-password`, `/request-password-reset`, and `/reset-password`.
- [x] Add DB-backed account route builders for `/list-accounts` and `/unlink-account`, leaving OAuth token/linking routes out of core scope for now.
- [x] Reorganize integration tests into grouped `tests/<domain>/main.rs` suites so API, auth, cookies, crypto, DB, context, env, rate limit, and utils coverage can grow without one flat directory.
- [x] Add disabled-path handling, trusted-origin checks, percent-decoded callback URL validation, Fetch Metadata CSRF checks, origin/path normalization hooks, strict/default trailing-slash route matching, and typed API errors.
- [x] Resolve static base URL/path at context initialization; keep dynamic request-derived URL support minimal and explicit.
- [x] Add plugin lookup helpers without porting client behavior.

## Remaining Parity Work

- [x] Implement real JWE cookie cache parity using Better Auth's `dir` + `A256CBC-HS512` strategy, HKDF-SHA256 key derivation, `kid` thumbprints, expiry claims, and secret rotation decode behavior.
- [x] Add dynamic trusted origins support with a Rust-owned request-aware provider API.
- [x] Replace plain API error bodies with structured JSON errors and stable error codes for origin, callback URL, CSRF, and not-found failures.
- [x] Expand endpoint contracts from plain function handlers into async endpoint + middleware chains that can support DB/network work and plugin hooks without framework coupling.
- [x] Implement full rate limiting behavior, including storage contracts, request keying, response headers, disabled-path interaction, and tests against the Better Auth route behavior.
- [x] Add router-level plugin hooks for `onRequest`, `onResponse`, middleware path matching, and endpoint conflict detection.
- [ ] Add `update-session` once OpenAuth has first-class additional session field configuration; upstream route only updates configured additional fields.
- [ ] Add email verification and email change routes once email callback/config contracts are modeled.
- [ ] Add delete-user routes once user deletion options, verification callbacks, and before/after hooks are modeled.
- [ ] Add OAuth account routes such as `/link-social`, `/get-access-token`, `/refresh-token`, `/account-info`, and callback routes in `openauth-oauth` rather than core.

## Continued Hardening

- [x] Re-export the new core API/plugin/rate-limit contracts from the public `openauth` crate.
- [x] Add `OpenAuth::handler_async` so the package-level initializer can serve async-capable router paths.
- [x] Reject database/secondary rate-limit storage selections unless a concrete `custom_storage` contract is provided.
- [x] Redact secret material from `Debug` output for options, environments, secret entries, secret configs, and context secret material.
- [x] Add request-aware dynamic rate-limit rule providers for parity with Better Auth custom rule functions.
- [x] Expose endpoint registry metadata and package-level extra endpoint initialization, with conflict detection.
- [x] Expose a public serializable/deserializable API error response body for integrations.

## Test Plan

- [x] `cargo test -p openauth-core --test api`
- [x] `cargo test -p openauth-core --test auth`
- [x] `cargo test -p openauth-core --test context`
- [x] `cargo test -p openauth-core --test cookies`
- [x] `cargo test -p openauth-core --test crypto`
- [x] `cargo test -p openauth-core --test db`
- [x] `cargo test -p openauth-core --test env`
- [x] `cargo test -p openauth-core --test rate_limit`
- [x] `cargo test -p openauth-core --test utils`
- [x] `cargo test -p openauth-core --test options`
- [x] `cargo test -p openauth --test public_api`
- [x] `cargo test --workspace`
- [x] `cargo fmt --all --check`
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings`

## Assumptions

- Better Auth is the behavior reference, not a TypeScript-shaped public API target.
- The initial API is HTTP-framework-neutral.
- `openauth-core` owns reusable primitives/contracts; `openauth` owns the package-level initializer and re-export surface.
- Client SDKs and concrete adapters are excluded.
- JWE support is implemented directly in core using `josekit` and HKDF-SHA256 for Better Auth cookie-cache parity; it can still be feature-gated later if dependency surface becomes an issue.
