# openauth-axum Implementation Checklist

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an Axum adapter crate that mounts OpenAuth's framework-neutral HTTP core under `/api/auth/*` or a custom `OpenAuthOptions.base_path`.

**Architecture:** `openauth-axum` is a thin framework adapter. It mounts a catch-all Axum router under the configured auth base path, converts Axum requests into `ApiRequest<Vec<u8>>`, calls `OpenAuth::handler_async`, and converts `ApiResponse<Vec<u8>>` back into Axum responses. Because routing stays in `AuthRouter`, core routes, extra endpoints, and plugin-provided routes are all supported automatically.

**Tech Stack:** Rust 2021, Axum 0.8, Tower test utilities, OpenAuth core/public crate.

---

### Task 1: Add Crate Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/openauth-axum/Cargo.toml`
- Create: `crates/openauth-axum/src/lib.rs`

- [x] Add `openauth-axum` as a workspace member and workspace dependency.
- [x] Add crate dependencies: `axum`, `openauth`, `serde_json`, `thiserror`, and dev `tower`.
- [x] Add an initial `lib.rs` with public API placeholders.

### Task 2: Implement Adapter API

**Files:**
- Modify: `crates/openauth-axum/src/lib.rs`

- [x] Implement `OpenAuthAxumExt` for `openauth::OpenAuth`.
- [x] Implement `router(auth)` to mount at `auth.context().base_path`.
- [x] Implement `routes(auth)` as an unmounted catch-all router for advanced custom mounting.
- [x] Implement `handle(auth, Request<Body>)` as the public escape hatch.
- [x] Add adapter options for configurable request body limits.
- [x] Mark adapter public configuration/error surfaces as non-exhaustive for release flexibility.
- [x] Preserve method, URI, version, headers, extensions, status, and repeated response headers.
- [x] Return JSON errors for body conversion and core handler failures.
- [x] Return `413 Payload Too Large` for requests that exceed the configured body limit.

### Task 3: Add End-to-End Tests

**Files:**
- Create: `crates/openauth-axum/tests/common/mod.rs`
- Create: `crates/openauth-axum/tests/routing.rs`
- Create: `crates/openauth-axum/tests/email_password.rs`
- Create: `crates/openauth-axum/tests/password.rs`
- Create: `crates/openauth-axum/tests/social.rs`
- Create: `crates/openauth-axum/tests/security.rs`

- [x] Test `/api/auth/ok` routing.
- [x] Test every core auth route is mounted through the Axum catch-all with the real method.
- [x] Test sign-up, sign-in, get-session, and sign-out over Axum.
- [x] Test password reset request and reset token consumption.
- [x] Test social OAuth sign-in and callback through mounted routes.
- [x] Test CSRF/origin behavior through Axum headers.
- [x] Test core rate limiting through Axum without adapter middleware.
- [x] Test custom base path.
- [x] Test manual nesting with `into_routes()`.
- [x] Test configurable body limits.
- [x] Test email verification happy path.
- [x] Test session additional field update happy path.
- [x] Test account list, unlink, account info, access token, and refresh token happy paths.
- [x] Test extra async endpoints are reachable through the catch-all.
- [x] Test plugin-provided endpoints are reachable through the catch-all.
- [x] Test user/session management happy paths over Axum: update user, list sessions, revoke a session, change password, and delete user.

### Task 4: Verify

**Commands:**
- [x] `cargo test -p openauth-axum`
- [x] `cargo test -p openauth-core`
- [x] `cargo test -p openauth --test public_api`
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings`
