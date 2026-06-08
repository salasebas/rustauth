# OpenAuth Agent Guide

OpenAuth is an unofficial Rust implementation inspired by Better Auth, not a
line-by-line port. For new features, behavior changes, tests, or public APIs,
use the upstream snapshot in `reference/upstream-better-auth/VERSION.md` as the
behavioral reference. Upstream source lives under
`reference/upstream-src/<parity-version>/repository/` and is gitignored; fetch it
with `./scripts/fetch-upstream-better-auth.sh` if missing. Do not commit
upstream clones.

Translate behavior into idiomatic Rust with explicit errors, focused modules,
and secure server-side boundaries. Discover crate ownership from `Cargo.toml`,
`crates/*/README.md`, and the existing source tree instead of duplicating repo
structure here.

## Verification

Before finishing code changes, run:

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate>
```

For security-sensitive or user-facing behavior, add focused tests that lock
down observable behavior, validation, serialization, error handling, and
integration contracts. When porting from Better Auth, inspect the matching
upstream tests and adapt the relevant scenarios to Rust.

## Tests

- Put **unit tests** next to the code they exercise (`#[cfg(test)]` modules in
  `src/`, or `mod tests` in the same file for small surfaces).
- Reserve each crate's `tests/` directory for **integration**, **contract**, or
  **end-to-end** coverage that needs a separate test binary (HTTP routes,
  adapters against services, cross-module wiring).
- **Fast vs slow is not the split between `src/` and `tests/`.** Most OpenAuth
  `tests/` targets are integration-fast (memory adapter, HTTP fixtures). Slow
  Docker or e2e tests stay in `tests/` too (`#[ignore]` or the Integration
  workflow in `.github/workflows/integration.yml`).
- Share integration helpers through `openauth_core::test_utils` (behind the
  `test-utils` feature) instead of copying fixture helpers across crates.

Before running integration tests that depend on external services, start the
required Docker Compose services with `./scripts/ensure-test-services.sh`.

## Dependencies

New dependencies are allowed, but propose them before adding them. Prefer
maintained, widely used libraries suitable for authentication or
security-sensitive code, and keep optional integrations behind feature flags.

## Release And Artifacts

For release work, read `RELEASE.md` first.

Use the local workspace `target/` directory by default. Do not delete build
artifacts or `/private/tmp` caches unless explicitly asked.
