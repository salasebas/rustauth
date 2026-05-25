# Telemetry Upstream Parity Audit Plan

## Summary

Goal: bring `openauth-telemetry` closer to Better Auth 1.6.9 server-side telemetry behavior while preserving Rust-native opt-in publishing, explicit test hooks, and privacy boundaries.

Baseline:

- Target crate: `crates/openauth-telemetry`.
- Upstream reference: `upstream/better-auth/1.6.9/repository/packages/telemetry`.
- Baseline verification before changes: `cargo test -p openauth-telemetry` passed 22 tests.
- Upstream telemetry has no auth routes, OpenAPI metadata, database schema, authorization checks, or request handlers.

## Files Inspected

Upstream:

- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/node.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/project-id.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/detectors/detect-auth-config.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/detectors/detect-database.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/detectors/detect-framework.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/detectors/detect-project-info.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/detectors/detect-runtime.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/detectors/detect-system-info.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/utils/hash.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/utils/id.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/utils/package-json.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/src/telemetry.test.ts`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/reference/telemetry.mdx`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/context/create-context.ts`
- `upstream/better-auth/1.6.9/repository/packages/cli/src/commands/generate.ts`
- `upstream/better-auth/1.6.9/repository/packages/cli/src/commands/migrate.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/env/env-impl.ts`

OpenAuth:

- `crates/openauth-telemetry/src/lib.rs`
- `crates/openauth-telemetry/src/types.rs`
- `crates/openauth-telemetry/src/auth_config.rs`
- `crates/openauth-telemetry/src/env.rs`
- `crates/openauth-telemetry/src/project_id.rs`
- `crates/openauth-telemetry/src/transport.rs`
- `crates/openauth-telemetry/src/detectors/*`
- `crates/openauth-telemetry/src/utils/*`
- `crates/openauth-telemetry/tests/telemetry.rs`
- `crates/openauth-telemetry/README.md`
- `crates/openauth/Cargo.toml`
- `crates/openauth/src/lib.rs`
- Relevant OpenAuth option definitions under `crates/openauth-core/src/options/*`.

## Confirmed Matches

- Telemetry is disabled by default.
- `OPENAUTH_TELEMETRY` and option-side enablement use upstream's `envEnabled || telemetryEnabled` shape.
- Test environments suppress telemetry unless `skip_test_check` is set.
- Missing endpoint plus missing custom track returns a hard no-op publisher.
- Custom track has priority over HTTP endpoint.
- Init telemetry is spawned asynchronously and does not block auth initialization.
- Later `publish` calls accept arbitrary event types and payloads.
- Publisher overwrites caller-provided `anonymousId` with the resolved project anonymous id.
- HTTP transport is injectable and posts JSON to the configured endpoint.
- Payload avoids raw `base_url`, app name, cookie prefix value, cookie domain value, secrets, tokens, and function bodies.
- Rust runtime, database, framework, system, and package-manager detectors are intentionally Rust-specific equivalents.
- With the `openauth-telemetry/oauth` feature, configured social providers are reported as redacted provider metadata without client ids or client secrets.

## Confirmed Differences

- `get_telemetry_auth_config` previously hardcoded several options that OpenAuth already models; this audit now maps email/password, password reset, session, account, and secondary storage flags.
- Config snapshot previously used stale upstream test keys (`onEmailVerification`, `sendChangeEmailVerification`); this audit now uses upstream source keys (`beforeEmailVerification`, `sendChangeEmailConfirmation`).
- Config snapshot previously included `advanced.database.useNumberId`; this audit removed it to match upstream source.
- `DetectionInfo.version` previously required `String`; this audit made it nullable.
- Package manager detection previously emitted `"unknown"` for missing Cargo version; this audit now emits `null`.
- Root `openauth` facade previously re-exported telemetry unconditionally; this audit gates re-exports behind the `telemetry` feature.

## Proposed Fixes

- Save this audit plan before code changes.
- Update focused tests first for config snapshot parity, env enablement/suppression, publish behavior, debug behavior, and detection version nullability.
- Populate config snapshot fields from already-modeled OpenAuth options and remove stale/non-upstream keys.
- Sanitize additional field metadata by serializing only type, required/input/returned flags, and boolean presence for default/db-name metadata.
- Change `DetectionInfo.version` to `Option<String>` and update detectors/tests.
- Make `openauth-telemetry` optional in `openauth`, add a `telemetry` feature, and gate facade re-exports.
- Update docs/examples impacted by the feature gate.
- Add OAuth-gated social provider metadata parity for safe provider options.

## Tests To Add Or Update

- Auth config snapshot reports modeled OpenAuth options without leaking raw secret, URL, cookie-domain, or callback data.
- Auth config snapshot uses upstream source key names and omits stale alias keys.
- Env parsing covers `true`, `1`, `0`, `false`, empty, and missing values through public telemetry behavior.
- `RUST_ENV=test` suppresses telemetry unless `skip_test_check` is true.
- Custom track wins over HTTP endpoint.
- Debug mode skips HTTP transport.
- Later publish calls preserve event type/payload and replace supplied anonymous ids.
- Detection info serializes nullable versions.
- OAuth-gated social providers include safe option metadata and never include client ids or client secrets.

## Current Server-Side Parity Estimate

Estimated server-only parity after this audit: **88%**.

Supported:

- Publisher lifecycle, enablement, debug behavior, test suppression, custom-track/HTTP transport behavior, anonymous project id shape, arbitrary event publishing, Rust-specific host detectors, redacted config snapshots for modeled OpenAuth options, root feature gating, and OAuth-gated social provider metadata.

Remaining gaps:

- OpenAuth has no telemetry wiring in core auth context initialization, so application code must call `create_telemetry` directly.
- CLI telemetry producers are not implemented in this crate; the publisher supports arbitrary events, but OpenAuth CLI event emission is outside this package.
- Rust social provider telemetry cannot safely introspect per-provider callback overrides such as `verifyIdToken` or `refreshAccessToken`; it reports stable trait/option metadata without invoking provider methods.
- Better Auth option fields not modeled in OpenAuth remain `null` or `false`, including global hooks, logger, onAPIError, model names/field mappings, verification cleanup, and advanced database generator details.
- Project ID generation is process-local and Rust/Cargo-based, not a line-by-line package.json cache port.

## Risks

- Removing stale alias keys may affect downstream consumers that copied the old Rust beta shape, but it matches upstream source behavior.
- Feature-gating telemetry in the facade is a public API change; the root crate should document enabling `features = ["telemetry"]` or using `openauth-telemetry` directly.

## Intentionally Left Unchanged

- Do not wire telemetry into `openauth-core::AuthContext` in this audit because that requires a separate dependency-boundary design.
- Do not add telemetry auth endpoints, admin/debug endpoints, migrations, database writes, or authorization checks.
- Do not port client/browser behavior.
- Do not put CLI event producers in the telemetry crate; arbitrary event publishing already supports future producers.
- Do not add new dependencies.
