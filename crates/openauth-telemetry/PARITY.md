# Server-Side Telemetry Parity

This crate tracks Better Auth **1.6.9** `@better-auth/telemetry` for server-only, opt-in anonymous usage analytics.

**Full parity documentation (tables, tests, detectors, config snapshot):**  
[`docs/parity/openauth-telemetry/README.md`](../../docs/parity/openauth-telemetry/README.md)

Historical implementation checklist:  
[`docs/superpowers/plans/2026-05-12-telemetry-upstream-checklist.md`](../../docs/superpowers/plans/2026-05-12-telemetry-upstream-checklist.md)

## Quick status

| Area | Server parity |
| --- | --- |
| Publisher / enablement / noop | High |
| `init` event shape | High (runtime/package manager differ by design) |
| Config snapshot | Medium–high (several branches fixed until `openauth-core` grows) |
| Host detectors | Medium (CPU model / RAM intentionally null) |
| JS-only detectors (Next, Prisma, npm UA) | N/A — Cargo/Rust equivalents |
| Package tests | Superset: **6** upstream Vitest → **33+** Rust tests |

Verify: `cargo test -p openauth-telemetry` (33 tests; 34 with `--features oauth`).

## Intentional Rust differences (summary)

- `OPENAUTH_*` env prefix; explicit env opt-out overrides `telemetry.enabled`.
- No default collector URL; hard noop without endpoint or `custom_track`.
- Runtime `rust`; DB/framework from `Cargo.toml`; package manager `cargo`.
- `build_async()` wires telemetry; sync `build()` keeps a noop publisher.
- CLI `dry_run` migrate outcome is OpenAuth-specific.

See the linked docs for field-level tables and test matrices.
