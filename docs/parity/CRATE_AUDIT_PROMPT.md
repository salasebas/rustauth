# Reusable prompt: deep parity audit for one crate

Copy this prompt into an agent session. Replace `{CRATE}` with the workspace crate
name (for example `openauth-scim`).

For splitting an oversized README parity section into `UPSTREAM.md`, use
[`UPSTREAM_SPLIT_PROMPT.md`](./UPSTREAM_SPLIT_PROMPT.md) instead.

---

You are auditing **upstream parity and hardening** for the OpenAuth Rust crate
`{CRATE}` against Better Auth **1.6.9**.

## Goal

Produce an accurate, evidence-based parity document in
`crates/{CRATE}/UPSTREAM.md`. Keep `crates/{CRATE}/README.md` crates.io-friendly:
usage docs plus a short **Better Auth compatibility** blurb linking to
`UPSTREAM.md`.

Do not create `docs/parity/{CRATE}/` folders or standalone `PARITY.md` files.

## Workflow

1. **Pin upstream**
   - Read `reference/upstream-better-auth/VERSION.md`.
   - If missing, run `./scripts/fetch-upstream-better-auth.sh`.
   - Open `reference/upstream-src/<version>/repository/`.

2. **Locate upstream surface**
   - Find the matching npm package under `packages/` (see
     [`docs/parity/README.md`](./README.md)).
   - Map exports from `package.json`, route registrations, plugin entrypoints, and
     `*.test.ts` / `*.spec.ts` files to Rust modules under
     `crates/{CRATE}/src/` and `crates/{CRATE}/tests/`.

3. **Inventory behavior**
   - List HTTP routes, public types, schema contributions, hooks, and config
     options in scope.
   - Note out-of-scope items (browser clients, TS-only inference, sibling crates).

4. **Measure tests**
   - Count Rust tests: `rg '#\[test\]|#\[tokio::test\]' crates/{CRATE}` or
     `cargo nextest run -p {CRATE} -- --list-tests`.
   - Count upstream tests in the mapped package.
   - Call out zero or shallow Rust coverage.

5. **Compare behavior**
   - Classify each major feature: **Implemented**, **Partial**, **Missing**, or
     **Intentional difference**.
   - Compare observable contracts: status codes, error codes, DB mutations,
     cookies, headers—not TypeScript types.

6. **Hardening / production risks**
   - Rate limits, fail-closed paths, races, idempotency, secrets, migrations,
     multi-instance concerns.

7. **Update `UPSTREAM.md` (English, tables)**

   Follow the template in [`UPSTREAM_SPLIT_PROMPT.md`](./UPSTREAM_SPLIT_PROMPT.md):
   summary table, feature parity table, test coverage table, intentional
   differences table, gaps/risks table, upstream lookup mapping table.

8. **Update README**

   At most 5 lines under `## Better Auth compatibility` + link to `./UPSTREAM.md`.

9. **Optional test maintainer note**
   - Refresh `crates/{CRATE}/tests/upstream_mapping.md` for large HTTP surfaces.
   - Do not add multi-pass audit documents.

## Constraints

- Server-side parity only unless the crate is a tooling/CLI surface.
- Idiomatic Rust: explicit errors; no silent fallbacks on auth boundaries.
- If you fix code, add tests and run:
  `cargo fmt --all --check`, `cargo clippy -p {CRATE} --all-targets -- -D warnings`,
  `cargo nextest run -p {CRATE}`.
- No stale links to removed `docs/parity/` trees or `superpowers` plans.

## Deliverable

- Updated `crates/{CRATE}/UPSTREAM.md` (table-heavy, scannable)
- Updated README compatibility blurb
- Summary: parity level, test delta vs upstream, top 3 open gaps (if any)
