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
   dependents), for example:
   - `openauth-core`
   - then crates that depend only on `openauth-core` (and std/external deps),
     such as `openauth-telemetry`
   - then `openauth` and any other crates that chain further dependencies  
   Use `cargo publish -p <crate-name>` from the repository root for each
   package.
6. Create a **GitHub release** tagging the commit that matches the published
   version.

When a CI workflow exists, expect it to mirror this sequence: verify the
workspace, build (`cargo package` / `cargo publish --dry-run`), publish each
crate, then attach release notes to the GitHub release.

A future **release preview** job (manual dispatch or PR label) would run
`cargo publish -p … --dry-run` (and checks) to validate publishes without
uploading.

## Crate names

Rust crate names match the `name` field in each `crates/*/Cargo.toml`. The
workspace currently includes:

- `openauth` — main umbrella crate (re-exports / integration surface)
- `openauth-core`
- `openauth-i18n`
- `openauth-oauth`
- `openauth-scim`
- `openauth-sso`
- `openauth-stripe`
- `openauth-telemetry`

Published versions on crates.io are whatever you ship from this repository;
they are **not** the official Better Auth npm packages.
