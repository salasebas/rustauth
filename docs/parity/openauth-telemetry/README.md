# Parity: `openauth-telemetry` ↔ `@better-auth/telemetry`

**Server-only** parity documentation between OpenAuth and Better Auth **v1.6.9**.

| Field | Value |
| --- | --- |
| Upstream npm | `@better-auth/telemetry@1.6.9` |
| Upstream path | `reference/upstream-src/1.6.9/repository/packages/telemetry/` |
| Rust crate | `crates/openauth-telemetry` |
| Parity pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |
| Historical checklist | [`docs/superpowers/plans/2026-05-12-telemetry-upstream-checklist.md`](../../superpowers/plans/2026-05-12-telemetry-upstream-checklist.md) |
| Crate summary | [`crates/openauth-telemetry/PARITY.md`](../../../crates/openauth-telemetry/PARITY.md) |

## Package relationship (no split/merge)

Unlike some monorepo areas, telemetry is **one upstream package → one Rust crate**.

| Role | Upstream | OpenAuth |
| --- | --- | --- |
| Anonymous usage telemetry | `@better-auth/telemetry` | `openauth-telemetry` |
| `telemetry.*` option types | `@better-auth/core` | `openauth-core` |
| Public re-export | `better-auth` | `openauth` (feature `telemetry`) |
| CLI producers | `packages/cli` (`generate`, `migrate`) | `openauth-cli` |
| OpenTelemetry traces | `@better-auth/core` instrumentation | **Out of scope** (not this package) |

## Index

| Document | Contents |
| --- | --- |
| [01-overview.md](./01-overview.md) | Executive summary, file map, scope / non-goals |
| [02-public-api.md](./02-public-api.md) | Public API, types, Cargo features, Rust extensions |
| [03-publisher-enablement.md](./03-publisher-enablement.md) | `create_telemetry`, env, transport, events |
| [04-auth-config-snapshot.md](./04-auth-config-snapshot.md) | `get_telemetry_auth_config` field by field |
| [05-detectors.md](./05-detectors.md) | Runtime, DB, framework, system, package manager |
| [06-integration.md](./06-integration.md) | `openauth`, `openauth-cli`, async wiring |
| [07-tests.md](./07-tests.md) | Upstream Vitest ↔ Rust matrix, extra coverage |
| [08-cli-events.md](./08-cli-events.md) | `cli_generate` / `cli_migrate` outcomes |
| [09-gaps-and-follow-ups.md](./09-gaps-and-follow-ups.md) | Gaps, upstream drift, **when to stop** |

## Quick verification

```bash
cargo test -p openauth-telemetry
cargo test -p openauth-telemetry --features oauth
```

Last verified: **33** Rust tests (default); **34** with `--features oauth`; upstream **6** Vitest.

## Summary status (server)

| Area | Server parity | Notes |
| --- | --- | --- |
| Publisher / enablement / noop | **High** | Rust adds explicit env opt-out/opt-in |
| `init` event | **High** | Same JSON shape; runtime/package manager differ by design |
| Config snapshot | **Medium–high** | Many fields aligned; several fixed `null`/`false` until `openauth-core` grows |
| Host detectors | **Medium** | Deploy vendors aligned; CPU model / RAM null without sysinfo |
| JS detectors (Next, Prisma, npm) | **N/A** | Cargo / Rust replacements |
| Package tests | **Superset** | All 6 upstream cases covered + ~27 extra Rust tests |
