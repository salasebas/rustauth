# Release Process

This release process is for the independent, unofficial **RustAuth** Rust
workspace. It is inspired by Better Auth but is not a 1:1 port, not affiliated
with, maintained by, endorsed by, or sponsored by the Better Auth project or
its maintainers.

This repository does not use Better Auth’s Changesets setup; that flow is
built around pnpm and npm package publishing.

RustAuth uses **Cargo** and is released **manually** via **crates.io** and
**GitHub releases**, following the steps below (same model as Tokio).

1. Bump the workspace version in the root `Cargo.toml` under
   `[workspace.package] version`. Member crates use `version.workspace = true`.
2. Align any **path dependency version pins** with the new release version (for
   example `rustauth-core = { path = "../rustauth-core", version = "…" }` in
   crates that depend on other workspace packages). Those semver constraints
   must match what you intend to publish on crates.io.
3. Refresh the lockfile: `cargo check` or `cargo build --workspace` so
   `Cargo.lock` reflects the bump (commit the lockfile change when it differs).
4. Run tests: `./scripts/ensure-test-services.sh postgres mysql redis valkey`,
   then `CARGO_INCREMENTAL=0 cargo nextest run --workspace --all-features`,
   then `CARGO_INCREMENTAL=0 cargo test --workspace --doc --all-features`.
5. Update the root `CHANGELOG.md` and each crate-level `CHANGELOG.md` with the
   release notes for the version being published.
6. Publish crates to crates.io in **dependency order** (dependencies before
   dependents). Use `cargo publish -p <crate-name>` from the repository root
   for each package, and wait for each newly published version to be visible
   on crates.io before publishing crates that depend on it.
7. Tag the release commit (`git tag vX.Y.Z && git push origin vX.Y.Z`) and create
   a **GitHub release** with notes from `CHANGELOG.md`.

## Publish order

The current workspace packages must be published in this order:

1. `rustauth-oauth` — no RustAuth workspace dependencies.
2. `rustauth-oidc` — no RustAuth workspace dependencies.
3. `rustauth-social-providers` — depends on `rustauth-oauth`.
4. `rustauth-core` — depends on `rustauth-oauth` and
   `rustauth-social-providers`.
5. `rustauth-diesel` — depends on `rustauth-core`.
6. `rustauth-stripe` — depends on `rustauth-core`.
7. `rustauth-saml` — depends on `rustauth-core`.
8. `rustauth-i18n` — depends on `rustauth-core`.
9. `rustauth-sqlx` — depends on `rustauth-core`.
10. `rustauth-telemetry` — depends on `rustauth-core`.
11. `rustauth-tokio-postgres` — depends on `rustauth-core`.
12. `rustauth-deadpool-postgres` — depends on `rustauth-core` and
    `rustauth-tokio-postgres`.
13. `rustauth-redis` — depends on `rustauth-core`.
14. `rustauth-plugins` — depends on `rustauth-core`, `rustauth-oauth`, and
    `rustauth-social-providers`; publish verification also uses
    `rustauth-redis` and `rustauth-sqlx`.
15. `rustauth-passkey` — depends on `rustauth-core`; publish verification also
    uses `rustauth-sqlx`.
16. `rustauth-sso` — depends on `rustauth-core`, `rustauth-oauth`,
    `rustauth-oidc`, and `rustauth-saml`; publish verification also uses
    `rustauth-sqlx`.
17. `rustauth-scim` — depends on `rustauth-core`; publish verification also
    uses `rustauth-deadpool-postgres`, `rustauth-plugins`, `rustauth-sqlx`, and
    `rustauth-tokio-postgres`.
18. `rustauth-oauth-provider` — depends on `rustauth-core` and
    `rustauth-plugins`.
19. `rustauth` — depends on `rustauth-core`,
    `rustauth-deadpool-postgres`, `rustauth-diesel`, `rustauth-i18n`,
    `rustauth-oidc`, `rustauth-passkey`, `rustauth-plugins`, `rustauth-saml`,
    `rustauth-scim`, `rustauth-sqlx`, `rustauth-sso`, `rustauth-stripe`,
    `rustauth-telemetry`, and `rustauth-tokio-postgres`.
20. `rustauth-fred` — depends on `rustauth-core`, and its publish
    verification uses a dev-dependency on `rustauth`.
21. `rustauth-axum` — depends on `rustauth`.
22. `rustauth-cli` — depends on `rustauth`, `rustauth-core`,
    `rustauth-plugins`, `rustauth-sqlx`, and optionally `rustauth-diesel`
    (via the `diesel` feature).

## Crate names

Rust crate names match the `name` field in each `crates/*/Cargo.toml`. The
workspace currently includes:

- `rustauth` — main umbrella crate (re-exports / integration surface)
- `rustauth-axum`
- `rustauth-cli`
- `rustauth-core`
- `rustauth-deadpool-postgres`
- `rustauth-diesel`
- `rustauth-fred`
- `rustauth-i18n`
- `rustauth-oidc`
- `rustauth-oauth`
- `rustauth-oauth-provider`
- `rustauth-passkey`
- `rustauth-plugins`
- `rustauth-redis`
- `rustauth-saml`
- `rustauth-scim`
- `rustauth-social-providers`
- `rustauth-sqlx`
- `rustauth-sso`
- `rustauth-stripe`
- `rustauth-telemetry`
- `rustauth-tokio-postgres`

Published versions on crates.io are whatever you ship from this repository;
they are **not** the official Better Auth npm packages.
