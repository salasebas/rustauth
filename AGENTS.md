# OpenAuth Agent Guide

OpenAuth is an unofficial Rust implementation inspired by Better Auth, not a
line-by-line port. Use the upstream snapshot documented in
`reference/upstream-better-auth/VERSION.md` as the behavioral reference for new
features, behavior changes, tests, or public APIs. Source lives under
`reference/upstream-src/<parity-version>/repository/` (gitignored). If missing,
run `./scripts/fetch-upstream-better-auth.sh`. Do not commit upstream clones.
Translate behavior into idiomatic Rust with explicit errors and secure
server-side boundaries.

Keep modules small and focused. Prefer discovering crate ownership from
`Cargo.toml`, `crates/*/README.md`, and the existing source tree instead of
relying on a duplicated structure list in this file.

## Acceptance Guide

Before finishing a change, verify only the modified crate or surface plus
plausible side effects such as public re-exports, feature gates, adapters,
examples, or integration crates. Do not run full
`--workspace --all-targets --all-features` checks by default unless the change
actually spans the workspace, changes feature composition, or prepares a
release/CI gate.

Use this local loop as the default shape:

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate>
```

For security-sensitive or user-facing behavior, add focused tests that lock
down observable behavior, validation, serialization, error handling, and
integration contracts. When porting from Better Auth, inspect the matching
upstream tests and adapt the relevant scenarios to Rust.

### Test placement

- Put **unit tests** next to the code they exercise (`#[cfg(test)]` modules in
  `src/`, or `mod tests` in the same file for small surfaces).
- Reserve each crate's `tests/` directory for **integration**, **contract**, or
  **end-to-end** coverage that needs a separate test binary (HTTP routes,
  adapters against services, cross-module wiring).
- **Fast vs slow is not the split between `src/` and `tests/`.** Most OpenAuth
  `tests/` targets are integration-fast (memory adapter, HTTP fixtures). Slow
  Docker or e2e tests stay in `tests/` too (`#[ignore]` or the Integration
  workflow). See `docs/ci/test-placement-audit.md`.
- Share integration helpers through `openauth_core::test_utils` (behind the
  `test-utils` feature) instead of copying fixture helpers across crates.

Before running integration tests that depend on external services, start the
required Docker Compose services with the repo helper. For SQLx/Postgres/MySQL
or distributed storage coverage, prefer:

```bash
./scripts/ensure-test-services.sh postgres mysql redis valkey
```

For narrower reruns, request only the services the affected tests need, such as
`./scripts/ensure-test-services.sh postgres mysql` before Postgres/MySQL
adapter or public API integration tests.

## Builds and Artifacts

Use the local workspace `target/` directory by default. Do not document or use
`CARGO_TARGET_DIR=/private/tmp/openauth-...` as a normal workflow because it
creates duplicate build caches outside the repository.

Use `CARGO_INCREMENTAL=0` for occasional heavy verification runs, not for the
normal scoped development loop:

```bash
CARGO_INCREMENTAL=0 cargo nextest run --workspace --all-features
CARGO_INCREMENTAL=0 cargo test --workspace --doc --all-features
```

Preview cleanup before deleting artifacts:

```bash
./scripts/cleanup-build-artifacts.sh --dry-run
```

Only delete `/private/tmp` artifacts with an explicit command that includes
`--apply --include-private-tmp`.

## Release Work

Before release-related changes, read `RELEASE.md` and follow its publish order,
verification commands, and versioning rules. Keep implementation crates on the
workspace version unless the release process explicitly changes that policy.

## Dependencies

New dependencies are allowed, but propose them before adding them. Prefer
maintained, widely used libraries suitable for authentication or
security-sensitive code, and keep optional integrations behind feature flags.
