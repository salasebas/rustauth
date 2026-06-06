# Reusable prompt: split README parity into UPSTREAM.md

Copy from the `---` line below into an agent session. Replace `{CRATE}` with the
workspace crate name (for example `openauth-scim`).

---

You are refactoring documentation for the OpenAuth crate `{CRATE}`.

## Goal

Move the full **Better Auth 1.6.9 upstream parity** content out of
`crates/{CRATE}/README.md` into a new or updated `crates/{CRATE}/UPSTREAM.md`.
Leave the README **crates.io-friendly**: usage docs only, plus a short Better Auth
compatibility blurb and a link to `UPSTREAM.md`.

Do **not** recreate `docs/parity/{CRATE}/`, `PARITY.md`, or audit checklists.

## Step 1 — Extract from README

1. Read `crates/{CRATE}/README.md`.
2. Find everything under `## Upstream parity (Better Auth 1.6.9)` (including
   nested `###` subsections).
3. Move that content into `UPSTREAM.md`. Improve clarity while moving—do not
   blindly copy sloppy prose.

## Step 2 — Write `UPSTREAM.md` (English, scannable)

Use this structure. Prefer **tables and bullet lists** over long paragraphs.

```markdown
# Upstream parity — {CRATE}

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
OpenAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/...` |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/.../` |
| **Rust crate** | `crates/{CRATE}/` |
| **Parity level** | High / Medium / Partial / N/A |
| **Scope** | Server-side only; list out-of-scope sibling crates |

## Summary

One short paragraph: what is ported, what is intentionally different, overall
confidence.

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| … | ✅ High / ⚠️ Partial / ❌ Missing / 🎯 Extension | One line each |

Use status emoji consistently: ✅ implemented, ⚠️ partial, ❌ missing,
🎯 OpenAuth extension (not in upstream 1.6.9), ➖ N/A (client-only upstream).

## Test coverage

| Surface | OpenAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Integration tests | N | M `it()` | command used to count |
| … | … | … | … |

Include the verify command:

```bash
cargo nextest run -p {CRATE}
```

Link to `tests/upstream_mapping.md` or `tests/support/*_parity.md` when present.

## Intentional differences

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| … | … | … | Security, idiomatic Rust, fail-closed, etc. |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G1 | … | Low / Med / High | … |

Keep the top 3–8 items that matter for production or parity work.

## Hardening notes

Short bullets: rate limits, idempotency, race conditions, secret handling,
multi-instance, migration safety—only what applies to this crate.

## Upstream lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is
   missing.
3. Open the upstream package directory listed above.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `src/routes.ts` | `src/routes.rs` |
| `src/*.test.ts` | `tests/...` |

5. Add a failing Rust test before behavior changes; match HTTP status, error
   codes, and DB side effects—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
```

Adapt sections: omit empty tables; add route inventories or plugin lists when
useful. Target **~80–150 lines** for large crates, **~40–80** for small ones.

## Step 3 — Shorten README

Replace the long parity section with:

```markdown
## Better Auth compatibility

Server-side {brief one-line description}. Aligned with Better Auth **1.6.9**
where it matters for this crate; OpenAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).
```

Place this section **after** Quick Start / Features and **before** Links (or
merge into Status if that reads better). Do not exceed **5 lines** plus the link.

Remove any stale references to `PARITY.md`, `docs/parity/{CRATE}/`, or
`docs/superpowers/`.

## Step 4 — Fix cross-references

Update links in the same crate that pointed at `#upstream-parity-better-auth-169`
in README—they should point to `UPSTREAM.md` instead.

Update `docs/parity/README.md` index row for `{CRATE}` to link to
`crates/{CRATE}/UPSTREAM.md` (only if you are batching all crates; otherwise
note it in the deliverable).

Delete obsolete stub files (`PARITY.md`, old `UPSTREAM_PARITY.md`) if they exist.

## Constraints

- English only.
- Do not change Rust code unless you find a broken doc test that references
  deleted paths—then fix the test.
- Preserve factual content from the README; reorganize for clarity.
- README must stay focused on **library users**; UPSTREAM.md on **contributors**.

## Deliverable

- `crates/{CRATE}/UPSTREAM.md` — formatted with tables
- `crates/{CRATE}/README.md` — short compatibility blurb + link
- List of any other files updated (tests, docs/parity index, etc.)
- One-line summary: parity level + test delta + top gap (if any)
