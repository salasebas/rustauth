# OpenAuth Agent Guide

## Project Intent

OpenAuth is an unofficial Rust implementation inspired by Better Auth. It is not
a 1:1 port. Preserve the intent and behavior that make sense, but design the
Rust API around Rust conventions, type safety, explicit errors, and secure
server-side boundaries.

This project is server-first. Port server behavior, core authentication
primitives, storage contracts, endpoints, sessions, tokens, OAuth/OIDC, SSO,
SCIM, SAML, Stripe integrations, validation, and adapters. Do not port
TypeScript-only or browser-only client code into the Rust core. Client SDKs can
exist later as thin wrappers around HTTP APIs, preferably generated or kept
small.

Before adding a new feature, behavior, test case, or public API, inspect the
matching Better Auth upstream implementation under `upstream/better-auth/`.
Use it as behavioral reference and product guidance, then translate the idea
into idiomatic Rust rather than copying the structure mechanically.

## Project Structure

- `crates/openauth`: public entry crate and re-export surface.
- `crates/openauth-core`: shared types, contracts, errors, primitives, and
  core authentication behavior.
- `crates/openauth-oauth`: OAuth and OpenID Connect support.
- `crates/openauth-sso`: enterprise SSO and SAML support.
- `crates/openauth-scim`: SCIM support.
- `crates/openauth-stripe`: Stripe billing and webhook integration.
- `crates/openauth-i18n`: internationalization support.
- `crates/openauth-telemetry`: telemetry support.
- `upstream/better-auth/`: upstream reference only. Check it before porting,
  but do not treat it as code to mirror line by line.

Keep modules small and focused. Split files when a module starts mixing
unrelated responsibilities or becomes hard to review in one pass.

## Testing

Write tests for security-sensitive and user-facing behavior. Prefer focused
tests that lock down observable behavior, error handling, validation,
serialization, and integration contracts.

Use Rust conventions:

- Small unit tests may live beside the implementation with `#[cfg(test)]`.
- Larger behavior tests should live in the crate-level `tests/` directory.
- When a feature grows, mirror the source structure under `tests/`.

Example:

```text
crates/openauth-core/src/plugin/admin/...
crates/openauth-core/tests/plugin/admin/...
```

When porting behavior from Better Auth, first check the upstream tests for the
same area and adapt the relevant scenarios to Rust.

## Versioning

Implementation crates should share the workspace version with
`version.workspace = true` for now. This keeps releases coherent while the
crate boundaries are still evolving.

Only split versioning later if a crate has a clear independent release cadence,
such as CLI tooling, telemetry, or other support packages.

## Engineering Rules

- Prefer idiomatic Rust APIs over TypeScript-shaped APIs.
- Model fallible operations with `Result` and typed errors.
- Do not use `unwrap()` or `expect()` in production code.
- Validate all external input at API boundaries.
- Treat redirects, tokens, sessions, secrets, signatures, webhooks, and crypto
  as security-critical.
- Keep public APIs small, explicit, and composable.
- Avoid large files and hidden global state.
- Use feature flags intentionally; do not force optional integrations into the
  core path.
- Preserve compatibility where practical, but prioritize correctness and
  security over matching upstream implementation details.

## Dependencies

New dependencies are allowed, but propose them before adding them. Prefer
libraries that are actively maintained, widely used, documented, and suitable
for authentication or security-sensitive code.

For official providers, use official SDKs when they exist and are appropriate.
If no official Rust SDK exists, wrap community crates or direct HTTP calls
behind OpenAuth-owned interfaces so the public API remains stable.
