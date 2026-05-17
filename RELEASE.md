# Release Process

This release process is for the independent, unofficial **OpenAuth** Rust
workspace. It is inspired by Better Auth but is not a 1:1 port, not affiliated
with, maintained by, endorsed by, or sponsored by the Better Auth project or
its maintainers.

This repository does not use Better Auth’s Changesets setup; that flow is
built around pnpm and npm package publishing.

OpenAuth uses **Cargo** and is intended to be released via **GitHub releases**
and **crates.io** (for example with OIDC trusted publishing from GitHub
Actions, analogous to PyPI Trusted Publishing). A release workflow is not wired
up in this repo yet; the steps below are the manual equivalent of what that
workflow would automate.

1. Bump the workspace version in the root `Cargo.toml` under
   `[workspace.package] version`. Member crates use `version.workspace = true`.
2. Align any **path dependency version pins** with the new release version (for
   example `openauth-core = { path = "../openauth-core", version = "…" }` in
   crates that depend on other workspace packages). Those semver constraints
   must match what you intend to publish on crates.io.
3. Refresh the lockfile: `cargo check` or `cargo build --workspace` so
   `Cargo.lock` reflects the bump (commit the lockfile change when it differs).
4. Run tests: `cargo test --workspace`.
5. Publish crates to crates.io in **dependency order** (dependencies before
   dependents). Use `cargo publish -p <crate-name>` from the repository root
   for each package, and wait for each newly published version to be visible
   on crates.io before publishing crates that depend on it.
6. Create a **GitHub release** tagging the commit that matches the published
   version.

When a CI workflow exists, expect it to mirror this sequence: verify the
workspace, build (`cargo package` / `cargo publish --dry-run`), publish each
crate, then attach release notes to the GitHub release.

A future **release preview** job (manual dispatch or PR label) would run
`cargo publish -p … --dry-run` (and checks) to validate publishes without
uploading.

## Publish order

The current workspace packages must be published in this order:

1. `openauth-oauth` — no OpenAuth workspace dependencies.
2. `openauth-scim` — no OpenAuth workspace dependencies.
3. `openauth-sso` — no OpenAuth workspace dependencies.
4. `openauth-stripe` — no OpenAuth workspace dependencies.
5. `openauth-social-providers` — depends on `openauth-oauth`.
6. `openauth-core` — depends on `openauth-oauth` and
   `openauth-social-providers`.
7. `openauth-i18n` — depends on `openauth-core`.
8. `openauth-plugins` — depends on `openauth-core`, `openauth-oauth`, and
   `openauth-social-providers`.
9. `openauth-sqlx` — depends on `openauth-core`.
10. `openauth-telemetry` — depends on `openauth-core`.
11. `openauth-tokio-postgres` — depends on `openauth-core`.
12. `openauth-deadpool-postgres` — depends on `openauth-core` and
    `openauth-tokio-postgres`.
13. `openauth-passkey` — depends on `openauth-core`.
14. `openauth-fred` — depends on `openauth-core`.
15. `openauth-redis` — depends on `openauth-core`.
16. `openauth-oauth-provider` — depends on `openauth-core` and
    `openauth-plugins`.
17. `openauth` — depends on `openauth-core`, `openauth-deadpool-postgres`,
    `openauth-passkey`, `openauth-plugins`, `openauth-sqlx`,
    `openauth-telemetry`, and `openauth-tokio-postgres`.
18. `openauth-axum` — depends on `openauth`.

## Crate names

Rust crate names match the `name` field in each `crates/*/Cargo.toml`. The
workspace currently includes:

- `openauth` — main umbrella crate (re-exports / integration surface)
- `openauth-axum`
- `openauth-core`
- `openauth-deadpool-postgres`
- `openauth-fred`
- `openauth-i18n`
- `openauth-oauth`
- `openauth-oauth-provider`
- `openauth-passkey`
- `openauth-plugins`
- `openauth-redis`
- `openauth-scim`
- `openauth-social-providers`
- `openauth-sqlx`
- `openauth-sso`
- `openauth-stripe`
- `openauth-telemetry`
- `openauth-tokio-postgres`

Published versions on crates.io are whatever you ship from this repository;
they are **not** the official Better Auth npm packages.
