# Upstream parity — rustauth

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
RustAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `better-auth` (public npm facade) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/better-auth/src/` (`index.ts`, `auth/full.ts`, `auth/minimal.ts`, `auth/base.ts`, `package.json` `exports`) |
| **Rust crate** | `crates/rustauth/` (`src/lib.rs`, `src/auth.rs`) |
| **Parity level** | **High** for core auth with default integrations; **Partial** for SAML and some product plugins |
| **Scope** | Server-side public entry crate. Out of scope: browser/React/Vue clients (`better-auth/client`, framework SDKs), CLI (`rustauth-cli`), HTTP mount (`rustauth-axum`), and runtime behavior owned by sibling crates listed below |

## Summary

The `rustauth` crate is the application-facing facade: it re-exports
[`rustauth-core`](../rustauth-core/UPSTREAM.md) (builder, handler, sessions, routes)
and optional integration crates behind Cargo features. Upstream has no separate
facade package—`better-auth` is the union of core server runtime plus optional
plugins and adapters. Parity for this crate is therefore **aggregate**: route and
crypto behavior is validated in `rustauth-core` and feature-specific crates;
`rustauth` tests lock the public re-export surface, initializer wiring, and
feature-flag dependency boundaries.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| `betterAuth()` / options builder | ✅ | `RustAuth::builder()`, `RustAuthBuilder` (`src/auth.rs`); async `build()` |
| `auth.handler(Request)` | ✅ | `RustAuth::handler` / `handler_async` delegate to `AuthRouter` |
| App-dev import surface | ✅ | `rustauth::prelude`; module paths for library-author APIs (`api`, `db`, `plugin`, …) |
| Feature-gated plugins | ✅ | `plugins`, `passkey`, `sso`, `scim`, `stripe`, `i18n`, `telemetry` features |
| Feature-gated enterprise | ⚠️ | `oidc`, `saml`, `saml-signed` — SAML remains experimental |
| SQL / Postgres adapters | ✅ | `sqlx-*`, `tokio-postgres`, `deadpool-postgres` re-exports |
| Schema / migrations API | ✅ | `create_schema`, `run_migrations` on `RustAuth` |
| OpenAPI / endpoint registry | ✅ | Re-exported from core router |
| `auth.api` programmatic caller | 🎯 | HTTP router is the Rust integration surface; no TS-style in-process API object |
| Browser / React / Vue clients | ➖ | Client-only upstream; not ported |
| Framework handlers (Next, Svelte, Node) | ➖ | [`rustauth-axum`](../rustauth-axum/UPSTREAM.md) and other adapter crates |

### Parity by concern (sibling crates)

| Concern | Parity crate |
| --- | --- |
| Builder, handler, sessions, accounts, routes | [`rustauth-core`](../rustauth-core/UPSTREAM.md) |
| Enterprise SSO (OIDC/SAML routes) | [`rustauth-sso`](../rustauth-sso/UPSTREAM.md) |
| OAuth/OIDC authorization server | [`rustauth-oauth-provider`](../rustauth-oauth-provider/UPSTREAM.md) |
| SQL / Redis persistence | [`rustauth-sqlx`](../rustauth-sqlx/UPSTREAM.md), [`rustauth-redis`](../rustauth-redis/UPSTREAM.md), … |
| Framework mount (Axum) | [`rustauth-axum`](../rustauth-axum/UPSTREAM.md) |
| Official plugins | [`rustauth-plugins`](../rustauth-plugins/UPSTREAM.md) |

## Test coverage

| Surface | RustAuth (Rust) | Upstream | Notes |
| --- | ---: | ---: | --- |
| **Total (default features)** | **45** | — | `cargo nextest list -p rustauth` |
| Public API / initializer contract | 48 | — | `tests/public_api.rs` (some `#[cfg(feature)]` gated) |
| Feature-flag dependency graph | 5 | — | `tests/feature_flags.rs` — SQLx dialect isolation, telemetry opt-in |
| Adapter DB hooks through umbrella | 3 | — | `tests/adapter_database_hooks.rs` |
| README doc example | 1 | — | `tests/docs.rs` |
| Facade `index.ts` / `auth/*.ts` Vitest | — | **0** dedicated | Upstream facade is thin; behavior tested in core + plugin packages |

```bash
cargo nextest run -p rustauth
```

Route-level and adapter parity suites live in sibling crates (start with
[`rustauth-core`](../rustauth-core/UPSTREAM.md)).

## Intentional differences

| Topic | Better Auth 1.6.9 | RustAuth | Why |
| --- | --- | --- | --- |
| Package layout | Single `better-auth` npm import | `rustauth` facade + focused workspace crates | Smaller compile units, explicit feature flags |
| `auth.api` in-process calls | `auth.api.getSession()` etc. | HTTP `handler_async` only | Idiomatic Rust server integration |
| Optional plugins | npm subpath / plugin imports | Cargo features (`sso`, `stripe`, …) | Compile-time dependency control |
| Telemetry | On when configured in JS | `telemetry` feature; off in default build | Opt-in binary size and network |
| OIDC vs SAML deps | Bundled in SSO plugin import graph | `oidc` feature excludes SAML/XML crates | Fail-closed dependency boundaries |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Aggregate parity only at this layer | Med | Facade tests do not replace `rustauth-core` route suites |
| G2 | SAML / `saml-signed` experimental | Med | Enable only with explicit risk acceptance |
| G3 | Feature ↔ upstream import drift | Low | New upstream plugins need matching Cargo feature + re-export in `lib.rs` |
| G4 | No browser/client SDK | Low | By design; server-only workspace |
| G5 | Re-export surface vs `package.json` exports | Low | `public_api.rs` guards key symbols; audit on major bumps |

## Hardening notes

- Default build excludes telemetry and all optional plugins—enable features explicitly.
- `oidc` feature must not pull SAML/XML stacks (`feature_flags` test).
- SQLx dialect features (`sqlx-postgres`, etc.) must not enable unrelated drivers.
- Async initializers (`build_async`, `rustauth_*_async`) work without `telemetry`.
- Use durable adapters and distributed rate-limit storage for multi-instance production
  (configured through re-exported core options).

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `packages/better-auth/src/` and `packages/better-auth/package.json` (`exports`).
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `packages/better-auth/src/index.ts` | `crates/rustauth/src/lib.rs` |
| `packages/better-auth/src/auth/full.ts`, `auth/minimal.ts` | `crates/rustauth/src/auth.rs` (`RustAuth`, `RustAuthBuilder`, `rustauth*`) |
| `packages/better-auth/src/auth/base.ts` (`handler`) | `RustAuth::handler` / `handler_async` → `rustauth-core` router |
| `packages/better-auth/src/plugins/*` | Feature-gated `rustauth_*` re-exports |
| `packages/better-auth/src/adapters/*` | `sqlx`, `tokio-postgres`, `deadpool-postgres`, `rustauth-redis`, … features |
| `packages/better-auth/src/integrations/*` | [`rustauth-axum`](../rustauth-axum/UPSTREAM.md) |
| Server `*.test.ts` under `better-auth/src/` | [`rustauth-core`](../rustauth-core/UPSTREAM.md) `tests/` (not duplicated here) |

5. Add a failing Rust test in the owning crate before behavior changes; match HTTP
   status, error codes, and DB side effects—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [rustauth-core UPSTREAM](../rustauth-core/UPSTREAM.md) — server runtime parity
- [Parity index](../../docs/parity/README.md)
