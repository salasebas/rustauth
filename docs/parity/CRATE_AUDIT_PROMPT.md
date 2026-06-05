# Reusable prompt: deep parity audit for one crate

Copy this prompt into an agent session. Replace `{CRATE}` with the workspace crate
name (for example `openauth-scim`).

---

You are auditing **upstream parity and hardening** for the OpenAuth Rust crate
`{CRATE}` against Better Auth **1.6.9**.

## Goal

Produce an accurate, evidence-based **Upstream parity (Better Auth 1.6.9)** section
in `crates/{CRATE}/README.md`. Do not create standalone `PARITY.md` files or new
`docs/parity/{CRATE}/` folders.

## Workflow

1. **Pin upstream**
   - Read `reference/upstream-better-auth/VERSION.md`.
   - If missing, run `./scripts/fetch-upstream-better-auth.sh`.
   - Open `reference/upstream-src/<version>/repository/`.

2. **Locate upstream surface**
   - Find the matching npm package under `packages/` (or monorepo path documented
     in the crate README / `docs/parity/README.md`).
   - Map exports from `package.json`, route registrations, plugin entrypoints, and
     `*.test.ts` / `*.spec.ts` files to Rust modules under
     `crates/{CRATE}/src/` and `crates/{CRATE}/tests/`.

3. **Inventory behavior**
   - List HTTP routes, public types, schema contributions, hooks, and config options
     that belong to this crate's scope.
   - Note intentional out-of-scope items (browser clients, TS-only inference, other
     npm packages handled by sibling crates).

4. **Measure tests**
   - Count Rust tests: `cargo nextest run -p {CRATE} -- --list-tests | wc -l` or
     `rg '#\[test\]|#\[tokio::test\]' crates/{CRATE}`.
   - Count upstream tests in the mapped package (`rg '^\s*(it|test)\(' …`).
   - Call out areas with zero or shallow Rust coverage.

5. **Compare behavior**
   - For each major feature: **Implemented**, **Partial**, **Missing**, or
     **Intentional difference** (with security/idiom rationale).
   - Prefer observable contracts: status codes, error codes, DB mutations, cookie
     names, headers—not TypeScript type shapes.

6. **Hardening / production risks**
   - Rate limits, fail-closed paths, race conditions, idempotency, secret handling,
     migration safety, multi-instance concerns.

7. **Update documentation (English only)**
   Rewrite `## Upstream parity (Better Auth 1.6.9)` in `crates/{CRATE}/README.md`
   with these subsections:

   ### Status
   - Upstream package path, parity level, test counts, scope boundary.

   ### Intentional differences
   - Rust/OpenAuth choices that diverge from upstream by design.

   ### Open gaps / risks
   - Missing behavior, untested paths, known production caveats.

   ### Upstream lookup
   - Pin file, upstream directory, how to map routes/tests to Rust, verify command
     (`cargo nextest run -p {CRATE}`).

8. **Optional test maintainer note**
   - For large HTTP surfaces, you may add or refresh
     `crates/{CRATE}/tests/upstream_mapping.md` (test name ↔ upstream test file).
   - Do not add audit checklists or multi-pass finding documents.

## Constraints

- Server-side parity only unless the crate is explicitly a client/tooling surface.
- Idiomatic Rust: explicit errors, no silent fallbacks on auth boundaries.
- If you fix code, add or extend focused tests and run:
  `cargo fmt --all --check`, `cargo clippy -p {CRATE} --all-targets -- -D warnings`,
  `cargo nextest run -p {CRATE}`.
- Keep the README section concise but complete (~25–60 lines). No stale links to
  removed `docs/parity/` trees or `superpowers` plans.

## Deliverable

- Updated `crates/{CRATE}/README.md` parity section grounded in source and tests.
- Short summary: parity level, test delta vs upstream, top 3 open gaps (if any).
