# Contributing

OpenAuth is an independent, unofficial Rust authentication toolkit inspired by
Better Auth. It is not affiliated with, maintained by, endorsed by, or sponsored
by the Better Auth project or its maintainers.

## Setup

```bash
./scripts/fetch-upstream-better-auth.sh
cargo install --locked cargo-nextest
```

Bring up optional integration services when needed:

```bash
./scripts/ensure-test-services.sh postgres mysql redis valkey
```

## Tests

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate>
```

## Porting Work

Each crate under `crates/` maps to an upstream Better Auth package when possible.
Record parity status in the crate README and, when a surface is closed out, in
`docs/parity/<crate>/` (see [`docs/parity/README.md`](docs/parity/README.md)).

When porting behavior:

1. Read the active pin in `reference/upstream-better-auth/VERSION.md`.
2. Inspect the matching package under
   `reference/upstream-src/<version>/repository/packages/`.
3. Write a focused Rust test.
4. Implement an idiomatic Rust equivalent with explicit errors.
5. Keep framework- or database-specific behavior in a dedicated crate.
6. Update the crate README parity section and the matching `docs/parity/` note when
   behavior, gaps, or test coverage change.

Do not add intermediate audit checklists or agent planning docs to the repo.
Keep closure/closeout notes concise and link them from the crate README.

## Pull Requests

Use conventional commit-style PR titles where possible.
