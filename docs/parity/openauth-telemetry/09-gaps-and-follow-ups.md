# 09 — Gaps, follow-ups, and when to stop

Closing document for **server-only** parity audit of `openauth-telemetry` ↔ `@better-auth/telemetry` v1.6.9.

## Verdict

| Question | Answer |
| --- | --- |
| Keep documenting this crate? | **No** for functional inventory — [01](./01-overview.md)–[08](./08-cli-events.md) is complete. |
| Remaining implementable parity? | Mostly **grow `openauth-core`** (snapshot) and **optional tests** (project id), not telemetry crate logic. |
| Next crate? | Another directory under [`docs/parity/`](../README.md) if the goal is whole-workspace parity. |

Server-only estimate (same as [`PARITY.md`](../../../crates/openauth-telemetry/PARITY.md)): **~97%** for publisher/init/CLI; **~70%** for config snapshot if every upstream hooks/logger boolean is required.

---

## Gaps that will **not** be closed in telemetry (by design)

| Gap | Reason |
| --- | --- |
| node/bun/deno runtime | Rust server |
| Detect Next/Nuxt/Prisma via npm | No `package.json` on typical server |
| `cpuModel` / `memory` | No `sysinfo` dep; weight and permissions |
| `appended` on `cli_generate` | CLI emits SQL, not TS schema append |
| `BETTER_AUTH_TELEMETRY_ID` | Upstream 1.6.9 does not consume it either |
| Conditional node/edge re-export | Single Rust artifact |

---

## Gaps owned by **other crates**

| Gap | Likely owner |
| --- | --- |
| `hooks`, `logger`, `databaseHooks` in snapshot | `openauth-core` options |
| `user.modelName`, `verification.*`, `onAPIError` | `openauth-core` |
| Real `password.hash` / `verify` booleans | Expose if core has hash hooks |
| `changeEmail.sendChangeEmailConfirmation` | `openauth-core` user options |
| Social flags from real callbacks | Trait metadata or introspection |
| Sync `build()` with telemetry | `openauth` API (documented; not a bug) |

---

## Optional follow-ups (low marginal value)

Only if a release needs “paper perfect” Better Auth analytics parity:

| Task | Effort | Value |
| --- | --- | --- |
| `project_id` tests (stable hash, random 32) | Low | Medium |
| Per deployment vendor env tests | Medium | Low |
| Optional `sysinfo` feature for `cpuModel`/`memory` | Medium | Low (privacy/weight) |
| Emit `appended` if CLI ever merges files | Low | Very low today |
| Sync [`2026-05-12-telemetry-upstream-checklist.md`](../../superpowers/plans/2026-05-12-telemetry-upstream-checklist.md) line by line | High | Low (duplicates these docs) |

**Recommendation:** treat this directory as source of truth; use the historical checklist only as an implementation backlog if needed.

---

## Known upstream drift (do not “fix” in OpenAuth)

| Source | Issue |
| --- | --- |
| `telemetry.test.ts` | Expects `onEmailVerification`; code uses `beforeEmailVerification` |
| `telemetry.test.ts` | Expects `sendChangeEmailVerification`; code uses `sendChangeEmailConfirmation` |
| `telemetry.test.ts` | `advanced.database.useNumberId` not in `detect-auth-config.ts` |

OpenAuth follows **implementation**, not stale tests.

---

## Documentation checklist (done)

- [x] 1:1 package mapping
- [x] Public API and env
- [x] Publisher / enablement / transport
- [x] Config snapshot field by field
- [x] Detectors
- [x] `openauth` / CLI integration
- [x] Test matrix (6 upstream ↔ 33 Rust, 34 with `oauth`)
- [x] CLI events and outcomes
- [x] Index in `docs/parity/README.md`
- [x] Links from `crates/openauth-telemetry/PARITY.md` and crate README

**Stop line for `openauth-telemetry`:** here.
