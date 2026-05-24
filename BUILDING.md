# Build and Cleanup Policy

This workspace has many crates and feature combinations. Treat full-workspace,
all-feature builds as verification gates, not as the default development loop.

## Daily Development

Prefer scoped commands for the crate or behavior you changed:

```bash
cargo check -p openauth-core
cargo nextest run -p openauth-core
cargo clippy -p openauth-core --all-targets -- -D warnings
```

Before finishing a task, run formatting, linting, and tests for the modified
crate plus any crates affected by public API, feature, adapter, or integration
changes. Do not run every workspace test by default during normal development.

## Heavy Verification

Use full gates when preparing a release, touching workspace-wide feature
composition, or validating broad side effects:

```bash
CARGO_INCREMENTAL=0 cargo nextest run --workspace --all-features
CARGO_INCREMENTAL=0 cargo test --workspace --doc --all-features
CARGO_INCREMENTAL=0 cargo lint-all
```

`CARGO_INCREMENTAL=0` is recommended for heavy, occasional runs because
incremental compilation stores extra state under `target/debug/incremental`.
Keep Cargo's default incremental behavior for normal scoped development.

## Target Directories

Use the local workspace `target/` directory by default. Do not set
`CARGO_TARGET_DIR=/private/tmp/openauth-...` for documented workflows; that
creates duplicate caches outside the repository with no obvious cleanup path.

For multiple worktrees or Codex sessions, prefer each worktree's local
`target/`. This uses more disk than a shared global target, but it isolates
sessions and makes cleanup predictable.

## Cleanup

Preview cleanup before deleting anything:

```bash
./scripts/cleanup-build-artifacts.sh --dry-run
```

Add `--show-sizes` when you need size reporting; it can be slow on very large
`target/` directories.

Apply cleanup for old local Cargo artifacts when `cargo-sweep` is installed:

```bash
./scripts/cleanup-build-artifacts.sh --apply --days 14
```

Include old OpenAuth-owned `/private/tmp` artifacts only when explicitly
requested:

```bash
./scripts/cleanup-build-artifacts.sh --apply --include-private-tmp --days 14
```

Install optional cleanup tooling with:

```bash
cargo install --locked cargo-sweep
```

`cargo-sweep` is optional because it removes old Cargo build artifacts without
forcing a full `cargo clean`, preserving recent build cache where possible.
