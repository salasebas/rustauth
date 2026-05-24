# OpenAuth Agent Guide

OpenAuth is an unofficial Rust implementation inspired by Better Auth, not a
line-by-line port. Use `upstream/better-auth/` as the behavioral reference for
new features, behavior changes, tests, or public APIs, then translate the
behavior into idiomatic Rust with explicit errors and secure server-side
boundaries.

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
