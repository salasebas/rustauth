# Upstream Parity: rustauth-telemetry

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` |
| Upstream package/path | `@better-auth/telemetry` server entry at `reference/upstream-src/1.6.9/repository/packages/telemetry/src/node.ts` |
| Rust crate | `rustauth-telemetry` |
| Parity level | High for publisher contract, anonymized payload shape, and auth config snapshot; partial only for host CPU/memory metrics |
| Scope | Server/runtime telemetry only |

## Summary

`rustauth-telemetry` tracks Better Auth's Node/server telemetry entry: publisher
shape, init event, anonymous project ID behavior, anonymized auth config
snapshot, and runtime detector payloads. It intentionally replaces Node/npm
discovery with Rust/Cargo signals and only sends telemetry to a
deployer-configured endpoint or custom sink.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Server entry exports | ✅ | Upstream `node.ts` exports `createTelemetry`, `getTelemetryAuthConfig`, and `TelemetryEvent`; Rust maps these to `create_telemetry`, `get_telemetry_auth_config`, and `TelemetryEvent`. |
| Publisher enablement | ✅ | Supports option-enabled telemetry, env opt-in, test suppression, and disabled publisher behavior. |
| No endpoint behavior | ✅ | Hard no-op unless `RUSTAUTH_TELEMETRY_ENDPOINT` or `TelemetryContext::custom_track` exists. |
| Endpoint transport | ✅ | Posts JSON through the `http` feature and ignores transport errors like upstream logs-and-continues behavior. |
| Custom track precedence | ✅ | Custom sink wins over configured endpoint. |
| Debug mode | ✅ | Debug skips HTTP posting and prints JSON. |
| Init event payload | ✅ | Emits `type`, `anonymousId`, and Better Auth-shaped `payload` with `config`, runtime, database, framework, environment, system info, and package manager. |
| Anonymous project ID | ✅ | Mirrors package/base URL/random fallback using Cargo package name instead of `package.json` name. |
| Auth config snapshot | ✅ | Shape matches upstream for modeled options, including `modelName`/`fields` aliases (redacted) and structured per-model `init_database_hooks` presence. |
| Social provider snapshot | ⚠️ | Covered behind `--features oauth`; provider credentials are redacted. |
| Runtime detection | 🎯 | Reports `rust` and crate version instead of Node. |
| Database/framework detection | 🎯 | Reads `Cargo.toml` dependency signals instead of `package.json` or `node_modules`. |
| Package manager detection | 🎯 | Reports Cargo from Rust environment signals instead of npm user agent. |
| System info | ⚠️ | Deployment vendor, OS, architecture, CPU count, Docker, WSL, TTY, and CI are modeled; CPU model/speed and memory stay `null`; Rust includes `isCI` in `systemInfo` while upstream only uses CI for environment detection. |
| HTTP routes/schemas/cookies | ➖ | Upstream telemetry package defines none. |

## Test Coverage

| Surface | RustAuth tests | Upstream tests | Notes |
| --- | --- | --- | --- |
| Publisher/init/no-op/env/debug/custom track | 19 integration tests | 5 server-relevant Vitest cases in `src/telemetry.test.ts` | Rust expands upstream cases for hard opt-out, endpoint/custom precedence, empty endpoint, debug env, async custom sink, and publish reuse. |
| Auth config snapshot | 3 integration tests | Covered inside upstream init payload test | Verifies modeled fields, schema alias presence, init `databaseHooks`, hook/logger/API-error presence, and redaction of secrets, base URL, DB names, and default values. |
| OAuth social-provider snapshot | 1 feature-gated integration test | Covered by upstream social provider config fields | Run with `--features oauth` when changing provider telemetry. |
| Rust detector units | 13 unit tests | Detector behavior mocked in upstream test | Covers Cargo manifest detection, env parsing, deployment vendor, system info basics, and package-manager detection. |
| Verify command | `cargo nextest run -p rustauth-telemetry` | `pnpm --filter @better-auth/telemetry test` upstream equivalent | Add `cargo nextest run -p rustauth-telemetry --features oauth` for OAuth snapshot coverage. |

## Intentional Differences

| Topic | Better Auth | RustAuth | Why |
| --- | --- | --- | --- |
| Env prefix | `BETTER_AUTH_TELEMETRY*` | `RUSTAUTH_TELEMETRY*` | Keeps Rust crate configuration under the RustAuth namespace. |
| Env false handling | `getBooleanEnvVar(..., false)` participates as an opt-in fallback | `RUSTAUTH_TELEMETRY=false` or `0` is a hard opt-out | Fail-closed behavior for authentication-adjacent telemetry. |
| Runtime | Server entry reports Node runtime | `rust` plus crate version | Host runtime is Rust, not JavaScript. |
| Project metadata | `package.json` package name | `Cargo.toml` package name | Rust projects do not require npm metadata. |
| Framework/database | JS package discovery | Cargo dependency discovery | Uses Rust ecosystem signals. |
| Package manager | npm user agent | Cargo presence/version | Matches Rust toolchain reality. |
| Collector ownership | Better Auth endpoint env | Deployer-supplied RustAuth endpoint or custom sink | RustAuth does not send telemetry to a maintainer endpoint by default. |
| Sensitive values | Mostly booleans/counts | Booleans/counts, with credentials and concrete values redacted | Avoids leaking secrets or deployment identifiers. |
| System metrics | Node build can read OS CPU/memory | No sysinfo dependency; some fields stay `null` | Keeps crate dependency footprint small. |
| Test/injection hooks | Vitest mocks and direct custom track | `TelemetryContext::test_hooks` and injectable `TelemetryHttpTransport` | Idiomatic Rust testability without changing production payload contracts. |

## Open Gaps / Risks

No open server-side parity gaps remain for this crate at pin `1.6.9`.

## Out of scope / intentional (not tracked as gaps)

| ID | Topic | Notes |
| --- | --- | --- |
| TEL-2 | Host system metrics | `cpuModel`, `cpuSpeed`, and `memory` stay `null` by design to avoid a `sysinfo` dependency; deployment vendor, OS, CPU count, Docker, WSL, TTY, and CI are reported. |
| TEL-3 | OAuth snapshot feature gate | Direct `rustauth-telemetry` consumers enable `--features oauth`; the umbrella `rustauth` crate enables it via its `telemetry` feature. |
| TEL-4 | Collector delivery guarantees | TLS, proxy behavior, retry policy, batching, and multi-instance analytics semantics are outside this crate contract (logs-and-continues transport only). |
| TEL-5 | Cloudflare Worker user-agent | Upstream checks `navigator.userAgent === "Cloudflare-Workers"`; Rust server hosts use deployment env vars only (no browser runtime). |

## Hardening Notes

- Telemetry is opt-in and remains a no-op without an endpoint or custom sink.
- `RUSTAUTH_TELEMETRY=false` and `RUSTAUTH_TELEMETRY=0` fail closed even when application options enable telemetry.
- Transport and custom sink failures do not abort auth flows.
- Config snapshots redact secrets, base URLs, client credentials, database names, and default field values.
- Test execution suppresses telemetry unless `TelemetryContext::skip_test_check` is set.

## Upstream Lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. If the upstream tree is missing, run `./scripts/fetch-upstream-better-auth.sh`.
3. Open `reference/upstream-src/1.6.9/repository/packages/telemetry/`.
4. Use `src/node.ts` as the canonical server entry.
5. Compare `src/node.ts`, shared detector files, shared utils, `src/types.ts`,
   and the server-relevant cases in `src/telemetry.test.ts` against the Rust
   files below.
6. Verify observable contracts: `init` event shape, `anonymousId` behavior,
   enablement/no-op rules, debug mode, endpoint/custom-track precedence,
   detector JSON, and redacted config fields.

| Upstream | Rust |
| --- | --- |
| `package.json` `exports["."].node` | `Cargo.toml`, `src/lib.rs` exports |
| `src/node.ts` `createTelemetry` | `src/lib.rs` `create_telemetry`, `TelemetryPublisher` |
| `@better-auth/core/env`, `getBooleanEnvVar`, `isTest`, `isCI` | `src/env.rs` |
| `betterFetch` POST transport | `src/transport.rs`, `TelemetryHttpTransport` |
| `src/detectors/detect-auth-config.ts` | `src/auth_config.rs` |
| `node.ts` project ID helper, `src/project-id.ts` fallback logic | `src/project_id.rs` |
| `src/utils/hash.ts`, `src/utils/id.ts` | `src/utils/hash.rs`, `src/utils/id.rs` |
| `src/detectors/detect-runtime.ts` | `src/detectors/runtime.rs` |
| `node.ts` `detectDatabaseNode`, `src/detectors/detect-database.ts` mapping | `src/detectors/database.rs`, `src/detectors/cargo_manifest.rs` |
| `node.ts` `detectFrameworkNode`, `src/detectors/detect-framework.ts` mapping | `src/detectors/framework.rs`, `src/detectors/cargo_manifest.rs` |
| `src/detectors/detect-project-info.ts` | `src/detectors/package_manager.rs` |
| `src/detectors/detect-system-info.ts`, node system info | `src/detectors/system_info.rs` |
| `src/types.ts` | `src/types.rs` |
| `src/telemetry.test.ts` | `tests/telemetry.rs` and detector unit tests |

## Links

- [README](./README.md)
- [Workspace parity index](../../docs/parity/README.md)
