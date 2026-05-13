# Telemetry Upstream Parity Implementation Plan

> **Guide note:** This document is a reusable parity guide, not a hard ceiling. If a target project adds behavior that covers the upstream intent in a safer, more idiomatic, or more complete way, mark the matching checklist item as completed and document the stronger behavior in the implementation notes for that project.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable server-side checklist for implementing Better Auth telemetry behavior in an idiomatic Rust OpenAuth package.

**Architecture:** Treat `upstream/better-auth/1.6.9/repository/packages/telemetry` as the behavioral reference, but translate the package into Rust server concerns instead of copying TypeScript runtime details. The Rust package should expose typed telemetry events, sanitized auth configuration snapshots, environment-controlled publishing, host/system detectors, and focused tests for privacy and transport behavior.

**Tech Stack:** Rust workspace crate, serde-compatible telemetry payloads, async transport abstraction, typed auth option snapshots, deterministic tests with mocked environment and transport.

**OpenAuth progress note (2026-05-12):** Checked items below mean the behavior is implemented in `crates/openauth-telemetry` and covered by the current Rust test suite. Verification command: `cargo test -p openauth-telemetry` (14 passed: 7 unit tests, 7 integration tests). Unchecked items may still be partially implemented, but are left open until there is focused test coverage for that behavior.

---

## Source Scope

Upstream package reviewed:

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
- `upstream/better-auth/1.6.9/repository/packages/telemetry/package.json`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/README.md`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/tsdown.config.ts`
- `upstream/better-auth/1.6.9/repository/packages/telemetry/tsconfig.json`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/reference/telemetry.mdx`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/reference/options.mdx`
- `upstream/better-auth/1.6.9/repository/packages/core/src/env/env-impl.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/types/init-options.ts`
- `upstream/better-auth/1.6.9/repository/packages/cli/src/commands/generate.ts`
- `upstream/better-auth/1.6.9/repository/packages/cli/src/commands/migrate.ts`

This checklist intentionally does not compare against any current OpenAuth implementation. Use it later as a parity matrix and mark items as completed only after inspecting the target project.

## Explicit Non-Goals

- [ ] Do not port browser-only or client SDK behavior.
- [ ] Do not mirror TypeScript package build details such as `tsdown`, ESM exports, or `typesVersions`.
- [ ] Do not expose raw secrets, base URLs, cookie domains, project names, callbacks, tokens, or function bodies in telemetry payloads.
- [ ] Do not make telemetry enabled by default.
- [ ] Do not let telemetry failures break authentication flows.
- [ ] Do not add HTTP auth endpoints just because other Better Auth packages use endpoint factories.
- [ ] Do not require OpenAPI metadata for telemetry unless the target project intentionally exposes telemetry admin/debug routes beyond upstream behavior.
- [ ] Do not conflate this anonymous usage telemetry package with Better Auth OpenTelemetry tracing/instrumentation; tracing spans belong in a separate instrumentation plan.

## Upstream Dependency And Import Checklist

These imports are part of the upstream behavior. In Rust, replace them with narrow local abstractions instead of coupling telemetry to unrelated framework code.

- [ ] `@better-auth/core` supplies `BetterAuthOptions`; Rust equivalent uses the target project's typed auth options or a sanitized view of them.
- [ ] `@better-auth/core/env` supplies `ENV`; Rust equivalent centralizes telemetry env reads behind a testable env provider.
- [ ] `@better-auth/core/env` supplies `getBooleanEnvVar`; Rust equivalent preserves the boolean parsing semantics.
- [ ] `@better-auth/core/env` supplies `isTest`; Rust equivalent preserves automatic test suppression.
- [ ] `@better-auth/core/env` supplies `logger`; Rust equivalent logs transport/custom-track errors without panicking.
- [ ] `@better-fetch/fetch` supplies HTTP `POST`; Rust equivalent uses a transport trait so the HTTP client is replaceable.
- [ ] `@better-auth/utils/hash` supplies SHA-256 hashing; Rust equivalent uses a maintained SHA-256 implementation.
- [ ] `@better-auth/utils/base64` supplies base64 encoding; Rust equivalent uses a maintained base64 implementation.
- [ ] `@better-auth/utils/random` supplies alphanumeric random strings; Rust equivalent uses a cryptographically suitable RNG for anonymous fallback ids.
- [ ] `type-fest` is TypeScript-only type support and should not create runtime requirements.
- [ ] Node built-ins `fs`, `fs/promises`, `os`, and `path` support Node-only package/system detection; Rust equivalent uses standard library or optional platform crates behind focused modules.
- [ ] `vitest` is test-only and maps to Rust unit/integration tests.
- [ ] `tsconfig.json` references `../core`; Rust equivalent should express crate dependencies explicitly and avoid circular imports.
- [ ] `package.json` peer dependencies are not runtime behavior by themselves; only imported functions above need Rust equivalents.
- [ ] `BETTER_AUTH_TELEMETRY_ID` exists in core env upstream but is not consumed by `packages/telemetry` in 1.6.9; do not require it for parity unless the target project intentionally adds a stronger override feature.

## Endpoint And OpenAPI Checklist

`packages/telemetry` upstream does not define API routes, auth endpoints, OpenAPI schemas, or `createAuthEndpoint` usage. Telemetry is emitted from initialization and CLI code paths.

- [ ] Confirm no upstream telemetry source file imports `createAuthEndpoint`.
- [ ] Confirm no upstream telemetry source file defines route handlers.
- [ ] Confirm no upstream telemetry source file attaches OpenAPI metadata.
- [ ] Keep telemetry publishing as an internal service/module, not a user-facing auth endpoint.
- [ ] If a target Rust project adds an admin/debug endpoint for telemetry inspection, put it in a separate module and mark upstream endpoint parity as not applicable.
- [ ] If a target Rust project adds such an endpoint, use the project's standard endpoint factory and OpenAPI conventions rather than wiring ad hoc routes.
- [ ] If a target Rust project adds such an endpoint, ensure it never exposes raw secrets, full config, user data, or live telemetry credentials.

## Upstream Drift And Compatibility Notes

These are places where the reviewed upstream package or adjacent tests/docs need careful interpretation.

- [ ] `detect-auth-config.ts` emits `emailVerification.beforeEmailVerification`.
- [ ] `telemetry.test.ts` expects `emailVerification.onEmailVerification`; verify whether this is an upstream stale test expectation before copying names.
- [ ] `packages/core/src/types/init-options.ts` defines `beforeEmailVerification`; prefer the current typed option name unless the target project supports an alias.
- [ ] `detect-auth-config.ts` emits `user.changeEmail.sendChangeEmailConfirmation`.
- [ ] `telemetry.test.ts` expects `user.changeEmail.sendChangeEmailVerification`; verify whether this is an upstream stale test expectation before copying names.
- [ ] `packages/core/src/types/init-options.ts` defines `sendChangeEmailConfirmation`; prefer the current typed option name unless the target project supports an alias.
- [ ] Docs describe runtime as Node/Bun/Deno, while `detectRuntime` also has an `edge` fallback; Rust implementation should document its own runtime names explicitly.
- [ ] Docs describe telemetry as anonymous aggregate usage analytics; this should drive privacy behavior even when implementation names differ.
- [ ] OpenTelemetry tracing docs under `reference/instrumentation.mdx` are adjacent but separate; do not merge span tracing requirements into this telemetry checklist.

## Suggested Rust File Map

Use this as a target shape when implementing in a Rust project. Adjust paths for the target workspace, but keep the responsibilities separated.

- [x] `crates/openauth-telemetry/src/lib.rs` exposes the public telemetry API and re-exports public types.
- [x] `crates/openauth-telemetry/src/types.rs` defines `TelemetryEvent`, `TelemetryContext`, `TelemetryConfigSnapshot`, detector structs, and publisher traits.
- [ ] `crates/openauth-telemetry/src/create.rs` builds telemetry publishers and implements enablement, init event, debug behavior, and no-op behavior.
- [ ] `crates/openauth-telemetry/src/auth_config.rs` converts auth options into a privacy-preserving config snapshot.
- [ ] `crates/openauth-telemetry/src/project_id.rs` creates stable anonymous project ids from sanitized inputs.
- [ ] `crates/openauth-telemetry/src/utils/hash.rs` implements SHA-256 plus base64 encoding for anonymous ids.
- [ ] `crates/openauth-telemetry/src/utils/id.rs` implements random fallback ids.
- [ ] `crates/openauth-telemetry/src/env.rs` reads telemetry environment flags through a testable abstraction.
- [x] `crates/openauth-telemetry/src/transport.rs` defines HTTP/custom-track publishing without binding core auth to one HTTP client.
- [ ] `crates/openauth-telemetry/src/detectors/runtime.rs` detects Rust/server runtime information.
- [ ] `crates/openauth-telemetry/src/detectors/environment.rs` detects production, CI, test, or development mode.
- [ ] `crates/openauth-telemetry/src/detectors/system.rs` detects host OS, architecture, CPU, memory, Docker, WSL, TTY, and deployment vendor where available.
- [x] `crates/openauth-telemetry/src/detectors/database.rs` detects configured database or adapter information.
- [x] `crates/openauth-telemetry/src/detectors/framework.rs` detects integration framework information when the host project provides it.
- [x] `crates/openauth-telemetry/src/detectors/package_manager.rs` records package-manager/build-tool metadata only when meaningful for a Rust server.
- [ ] `crates/openauth-telemetry/src/detectors/mod.rs` keeps detector exports explicit and avoids one large detector file.
- [ ] `crates/openauth-telemetry/src/utils/mod.rs` keeps hashing/id helpers explicit and small.
- [ ] `crates/openauth-telemetry/src/payload.rs` builds init payloads without mixing detector implementations into publisher code.
- [x] `crates/openauth-telemetry/tests/telemetry.rs` covers publisher behavior and init payload parity.
- [ ] `crates/openauth-telemetry/tests/auth_config.rs` covers privacy-preserving config snapshots.
- [ ] `crates/openauth-telemetry/tests/detectors.rs` covers deterministic detector behavior through mocked env/host inputs.
- [ ] `crates/openauth-telemetry/tests/project_id.rs` covers stable anonymous ids and random fallback behavior.

## Modularization Checklist

- [ ] Keep public API definitions separate from transport implementation.
- [ ] Keep auth config snapshot conversion separate from auth option definitions.
- [ ] Keep detector modules independent so they can be tested without initializing telemetry.
- [ ] Keep project id generation separate from publish/transport behavior.
- [ ] Keep platform-specific system probing isolated behind `system` detector functions.
- [ ] Keep environment parsing isolated behind an env provider to avoid global-state-heavy tests.
- [ ] Keep HTTP transport optional or feature-gated if the target Rust project supports no-network builds.
- [ ] Keep CLI event producers outside the telemetry crate; telemetry should accept events, not know CLI command internals.
- [ ] Keep any future endpoint/OpenAPI integration outside the telemetry publishing core.

## Public API Checklist

- [x] `createTelemetry` equivalent exists as an async Rust constructor.
- [x] Constructor accepts auth options or a stable sanitized options view.
- [x] Constructor accepts optional telemetry context.
- [x] Constructor returns an object with a `publish` operation.
- [x] `publish` accepts arbitrary typed telemetry events.
- [x] Public event type includes `type`, `payload`, and optional `anonymousId` equivalent.
- [x] Public context type includes `customTrack` equivalent.
- [ ] Public context type includes `database` override.
- [ ] Public context type includes `adapter` override.
- [x] Public context type includes `skipTestCheck` equivalent for tests.
- [x] `getTelemetryAuthConfig` equivalent is exported or made available for tests/integrations.
- [x] Telemetry API is available from the telemetry crate.
- [ ] If the root OpenAuth crate re-exports telemetry, it does so behind the intended feature or module boundary.

## Enablement And Transport Checklist

- [x] Telemetry is disabled by default when options do not enable it.
- [ ] `BETTER_AUTH_TELEMETRY=true` equivalent enables telemetry.
- [ ] `BETTER_AUTH_TELEMETRY=1` equivalent enables telemetry.
- [x] Explicit `options.telemetry.enabled=true` equivalent enables telemetry.
- [x] Explicit `options.telemetry.enabled=false` keeps telemetry disabled unless the environment flag enables it, matching upstream `envEnabled || telemetryEnabled`.
- [ ] Boolean env parser treats missing env as the supplied fallback.
- [ ] Boolean env parser treats `0` as false.
- [ ] Boolean env parser treats `false` as false case-insensitively.
- [ ] Boolean env parser treats an empty string as false.
- [ ] Boolean env parser treats any other non-empty value as true.
- [ ] Test environment suppresses telemetry by default.
- [ ] `skipTestCheck=true` equivalent allows telemetry in tests.
- [x] Missing telemetry endpoint plus missing custom track returns a no-op publisher.
- [x] No-op publisher accepts publish calls without side effects.
- [ ] Custom track is preferred over HTTP endpoint when both exist.
- [x] Custom track errors are caught and logged.
- [ ] HTTP transport errors are caught and logged.
- [ ] Debug mode can be enabled with `options.telemetry.debug=true`.
- [ ] Debug mode can be enabled with `BETTER_AUTH_TELEMETRY_DEBUG=true` equivalent.
- [ ] Debug mode logs the event payload instead of posting it to the endpoint.
- [ ] Normal HTTP publishing sends `POST` with the telemetry event body.
- [x] Init event is emitted asynchronously during constructor setup when telemetry is enabled.
- [ ] Later `publish` calls reuse the same anonymous id.
- [ ] Later `publish` calls preserve caller-provided `type`.
- [ ] Later `publish` calls preserve caller-provided `payload`.
- [ ] Later `publish` calls replace any caller-provided anonymous id with the project anonymous id.
- [x] Telemetry publishing never blocks or fails the auth initialization path with an uncaught error.

## External Producer Event Checklist

The telemetry package accepts arbitrary events. Upstream CLI uses that surface, so the telemetry crate should not hard-code only `init`.

- [ ] Publisher supports event types beyond `init`.
- [ ] Publisher supports payload maps/objects with command-specific data.
- [ ] CLI-style events are treated as producer payloads, not as telemetry crate internals.
- [ ] CLI producer failures are catchable without failing the user command.
- [ ] `cli_generate` event type is supported as an arbitrary event.
- [ ] `cli_generate` payload can include `outcome`.
- [ ] `cli_generate` outcome `generated` is representable.
- [ ] `cli_generate` outcome `overwritten` is representable.
- [ ] `cli_generate` outcome `appended` is representable.
- [ ] `cli_generate` outcome `no_changes` is representable.
- [ ] `cli_generate` outcome `aborted` is representable.
- [ ] `cli_generate` payload can include redacted `config`.
- [ ] `cli_generate` payload can include context-derived `adapter`.
- [ ] `cli_generate` payload can include context-derived `database`.
- [ ] `cli_migrate` event type is supported as an arbitrary event.
- [ ] `cli_migrate` payload can include `outcome`.
- [ ] `cli_migrate` outcome `migrated` is representable.
- [ ] `cli_migrate` outcome `no_changes` is representable.
- [ ] `cli_migrate` outcome `aborted` is representable.
- [ ] `cli_migrate` outcome `unsupported_adapter` is representable.
- [ ] `cli_migrate` payload can include adapter id when relevant.
- [ ] CLI payload adapter id is sanitized as a generic id, not adapter internals.
- [ ] CLI payload always uses the same redacted config snapshot rules as init telemetry.
- [ ] Server-only OpenAuth projects may mark CLI producer items as not applicable if they do not ship CLI tooling.

## Init Event Payload Checklist

The upstream init event has `type: "init"` and this payload shape.

- [x] `payload.config` includes the sanitized auth config snapshot.
- [x] `payload.runtime` includes runtime name and nullable version.
- [x] `payload.database` includes detected database name and nullable version when known.
- [x] `payload.framework` includes detected framework name and nullable version when known.
- [x] `payload.environment` is one of production, ci, test, or development.
- [ ] `payload.systemInfo` includes host/deployment system fields.
- [x] `payload.packageManager` includes package manager/build tool name and version when known.
- [x] Init event includes `anonymousId`.
- [ ] Init event does not include `baseURL`.
- [ ] Init event does not include `appName`.
- [ ] Init event does not include cookie prefix values.
- [ ] Init event does not include cookie domain values.
- [ ] Init event does not include callback function bodies.
- [ ] Init event does not include OAuth tokens, secrets, signing keys, webhook secrets, passwords, or connection strings.

## Auth Config Snapshot Checklist

### Context Fields

- [ ] Include `database` from telemetry context.
- [ ] Include `adapter` from telemetry context.
- [ ] Do not infer raw database URLs from config.
- [ ] Do not include adapter internals beyond a safe name/string.

### Email Verification

- [ ] `sendVerificationEmail` is represented as boolean presence.
- [ ] `sendOnSignUp` is represented as boolean.
- [ ] `sendOnSignIn` is represented as boolean.
- [ ] `autoSignInAfterVerification` is represented as boolean.
- [ ] `expiresIn` value is included when configured.
- [ ] `beforeEmailVerification` is represented as boolean presence.
- [ ] If supporting Better Auth compatibility aliases, `onEmailVerification` maps to the same sanitized boolean without duplicating sensitive callback data.
- [ ] `afterEmailVerification` is represented as boolean presence.
- [ ] Function bodies are never serialized.

### Email And Password

- [ ] `enabled` is represented as boolean.
- [ ] `disableSignUp` is represented as boolean.
- [ ] `requireEmailVerification` is represented as boolean.
- [ ] `maxPasswordLength` value is included when configured.
- [ ] `minPasswordLength` value is included when configured.
- [ ] `sendResetPassword` is represented as boolean presence.
- [ ] `resetPasswordTokenExpiresIn` value is included when configured.
- [ ] `onPasswordReset` is represented as boolean presence.
- [ ] `password.hash` is represented as boolean presence.
- [ ] `password.verify` is represented as boolean presence.
- [ ] `autoSignIn` is represented as boolean.
- [ ] `revokeSessionsOnPasswordReset` is represented as boolean.

### Social Providers

- [ ] Snapshot includes one item per configured social provider.
- [ ] Provider config can be resolved if it is lazily produced by a server-side factory.
- [ ] Provider item includes `id`.
- [ ] Provider item includes `mapProfileToUser` as boolean presence.
- [ ] Provider item includes `disableDefaultScope` as boolean.
- [ ] Provider item includes `disableIdTokenSignIn` as boolean.
- [ ] Provider item includes `disableImplicitSignUp`.
- [ ] Provider item includes `disableSignUp`.
- [ ] Provider item includes `getUserInfo` as boolean presence.
- [ ] Provider item includes `overrideUserInfoOnSignIn` as boolean.
- [ ] Provider item includes `prompt` value when configured.
- [ ] Provider item includes `verifyIdToken` as boolean presence.
- [ ] Provider item includes `scope` value when configured.
- [ ] Provider item includes `refreshAccessToken` as boolean presence.
- [ ] Provider item never includes client id.
- [ ] Provider item never includes client secret.
- [ ] Provider item never includes issuer secrets, private keys, tokens, or raw credentials.

### Plugins

- [ ] Snapshot includes plugin ids as strings.
- [ ] Snapshot does not include plugin callback functions.
- [ ] Snapshot does not include plugin implementation details.

### User Model

- [ ] `modelName` is included when configured.
- [ ] `fields` is included when configured and safe.
- [ ] `additionalFields` is included when configured and safe.
- [ ] `changeEmail.enabled` is included when configured.
- [ ] `changeEmail.sendChangeEmailConfirmation` is represented as boolean presence.
- [ ] If supporting Better Auth compatibility aliases, `changeEmail.sendChangeEmailVerification` maps to the same sanitized boolean without duplicating sensitive callback data.
- [ ] No email addresses or user data are included.

### Verification Model

- [ ] `modelName` is included when configured.
- [ ] `disableCleanup` is included when configured.
- [ ] `fields` is included when configured and safe.
- [ ] No verification identifiers or token values are included.

### Session Model

- [ ] `modelName` is included when configured.
- [ ] `additionalFields` is included when configured and safe.
- [ ] `cookieCache.enabled` is included when configured.
- [ ] `cookieCache.maxAge` is included when configured.
- [ ] `cookieCache.strategy` is included when configured.
- [ ] `disableSessionRefresh` is included when configured.
- [ ] `expiresIn` is included when configured.
- [ ] `fields` is included when configured and safe.
- [ ] `freshAge` is included when configured.
- [ ] `preserveSessionInDatabase` is included when configured.
- [ ] `storeSessionInDatabase` is included when configured.
- [ ] `updateAge` is included when configured.
- [ ] Session ids, tokens, cookies, and signed cookie values are never included.

### Account Model

- [ ] `modelName` is included when configured.
- [ ] `fields` is included when configured and safe.
- [ ] `encryptOAuthTokens` is included when configured.
- [ ] `updateAccountOnSignIn` is included when configured.
- [ ] `accountLinking.enabled` is included when configured.
- [ ] `accountLinking.trustedProviders` is included when configured.
- [ ] `accountLinking.updateUserInfoOnLink` is included when configured.
- [ ] `accountLinking.allowUnlinkingAll` is included when configured.
- [ ] OAuth access tokens, refresh tokens, id tokens, and account credentials are never included.

### Hooks And Storage

- [ ] `hooks.after` is represented as boolean presence.
- [ ] `hooks.before` is represented as boolean presence.
- [ ] `secondaryStorage` is represented as boolean presence.
- [ ] Hook function bodies are never included.
- [ ] Storage implementation internals are never included.

### Advanced Options

- [ ] `cookiePrefix` is represented as boolean presence, not the actual prefix.
- [ ] `cookies` is represented as boolean presence.
- [ ] `crossSubDomainCookies.domain` is represented as boolean presence, not the actual domain.
- [ ] `crossSubDomainCookies.enabled` value is included when configured.
- [ ] `crossSubDomainCookies.additionalCookies` is included only if it is safe metadata.
- [ ] `database.generateId` is included only as safe metadata or boolean presence if it is a function.
- [ ] `database.defaultFindManyLimit` is included when configured.
- [ ] `useSecureCookies` is included when configured.
- [ ] `ipAddress.disableIpTracking` is included when configured.
- [ ] `ipAddress.ipAddressHeaders` is included when configured and safe.
- [ ] `disableCSRFCheck` is included when configured.
- [ ] `defaultCookieAttributes.expires` is included when configured.
- [ ] `defaultCookieAttributes.secure` is included when configured.
- [ ] `defaultCookieAttributes.sameSite` is included when configured.
- [ ] `defaultCookieAttributes.domain` is represented as boolean presence, not the actual domain.
- [ ] `defaultCookieAttributes.path` is included when configured.
- [ ] `defaultCookieAttributes.httpOnly` is included when configured.

### Trusted Origins

- [ ] `trustedOrigins` is represented as a count.
- [ ] Trusted origin values are never included.

### Rate Limit

- [ ] `storage` is included when configured and safe.
- [ ] `modelName` is included when configured.
- [ ] `window` is included when configured.
- [ ] `customStorage` is represented as boolean presence.
- [ ] `enabled` is included when configured.
- [ ] `max` is included when configured.

### API Error Handling

- [ ] `errorURL` is included only if the project considers it non-sensitive; otherwise represent as boolean presence.
- [ ] `onError` is represented as boolean presence.
- [ ] `throw` is included when configured.
- [ ] Error callback function bodies are never included.

### Logger

- [ ] `disabled` is included when configured.
- [ ] `level` is included when configured.
- [ ] `log` is represented as boolean presence.
- [ ] Logger implementation internals are never included.

### Database Hooks

- [ ] `databaseHooks.user.create.after` is represented as boolean presence.
- [ ] `databaseHooks.user.create.before` is represented as boolean presence.
- [ ] `databaseHooks.user.update.after` is represented as boolean presence.
- [ ] `databaseHooks.user.update.before` is represented as boolean presence.
- [ ] `databaseHooks.session.create.after` is represented as boolean presence.
- [ ] `databaseHooks.session.create.before` is represented as boolean presence.
- [ ] `databaseHooks.session.update.after` is represented as boolean presence.
- [ ] `databaseHooks.session.update.before` is represented as boolean presence.
- [ ] `databaseHooks.account.create.after` is represented as boolean presence.
- [ ] `databaseHooks.account.create.before` is represented as boolean presence.
- [ ] `databaseHooks.account.update.after` is represented as boolean presence.
- [ ] `databaseHooks.account.update.before` is represented as boolean presence.
- [ ] `databaseHooks.verification.create.after` is represented as boolean presence.
- [ ] `databaseHooks.verification.create.before` is represented as boolean presence.
- [ ] `databaseHooks.verification.update.after` is represented as boolean presence.
- [ ] `databaseHooks.verification.update.before` is represented as boolean presence.
- [ ] Hook function bodies are never included.

## Detector Checklist

### Runtime

Upstream detects Deno, Bun, Node, and edge. In Rust, preserve the intent: identify the server runtime/host without pretending to be a JavaScript runtime.

- [x] Runtime detector returns a name.
- [x] Runtime detector returns nullable or optional version.
- [x] Rust implementation records a Rust/OpenAuth server runtime name suitable for server telemetry.
- [ ] Rust implementation records crate/app version when available and safe.
- [x] Rust implementation does not rely on browser globals.
- [x] Rust implementation does not require Node, Bun, or Deno globals.

### Environment

- [ ] `NODE_ENV=production` upstream behavior maps to production detection where applicable.
- [ ] CI detection takes precedence over test/development when production is not set.
- [ ] Test detection returns `test`.
- [ ] Missing production/CI/test indicators returns `development`.
- [ ] CI detector treats `CI=false` as not CI.
- [ ] CI detector recognizes `BUILD_ID`.
- [ ] CI detector recognizes `BUILD_NUMBER`.
- [ ] CI detector recognizes `CI`.
- [ ] CI detector recognizes `CI_APP_ID`.
- [ ] CI detector recognizes `CI_BUILD_ID`.
- [ ] CI detector recognizes `CI_BUILD_NUMBER`.
- [ ] CI detector recognizes `CI_NAME`.
- [ ] CI detector recognizes `CONTINUOUS_INTEGRATION`.
- [ ] CI detector recognizes `RUN_ID`.

### Deployment Vendor

- [ ] Detect Cloudflare from `CF_PAGES`.
- [ ] Detect Cloudflare from `CF_PAGES_URL`.
- [ ] Detect Cloudflare from `CF_ACCOUNT_ID`.
- [ ] Detect Vercel from `VERCEL`.
- [ ] Detect Vercel from `VERCEL_URL`.
- [ ] Detect Vercel from `VERCEL_ENV`.
- [ ] Detect Netlify from `NETLIFY`.
- [ ] Detect Netlify from `NETLIFY_URL`.
- [ ] Detect Render from `RENDER`.
- [ ] Detect Render from `RENDER_URL`.
- [ ] Detect Render from `RENDER_INTERNAL_HOSTNAME`.
- [ ] Detect Render from `RENDER_SERVICE_ID`.
- [ ] Detect AWS from `AWS_LAMBDA_FUNCTION_NAME`.
- [ ] Detect AWS from `AWS_EXECUTION_ENV`.
- [ ] Detect AWS from `LAMBDA_TASK_ROOT`.
- [ ] Detect GCP from `GOOGLE_CLOUD_FUNCTION_NAME`.
- [ ] Detect GCP from `GOOGLE_CLOUD_PROJECT`.
- [ ] Detect GCP from `GCP_PROJECT`.
- [ ] Detect GCP from `K_SERVICE`.
- [ ] Detect Azure from `AZURE_FUNCTION_NAME`.
- [ ] Detect Azure from `FUNCTIONS_WORKER_RUNTIME`.
- [ ] Detect Azure from `WEBSITE_INSTANCE_ID`.
- [ ] Detect Azure from `WEBSITE_SITE_NAME`.
- [ ] Detect Deno Deploy from `DENO_DEPLOYMENT_ID`.
- [ ] Detect Deno Deploy from `DENO_REGION`.
- [ ] Detect Fly.io from `FLY_APP_NAME`.
- [ ] Detect Fly.io from `FLY_REGION`.
- [ ] Detect Fly.io from `FLY_ALLOC_ID`.
- [ ] Detect Railway from `RAILWAY_STATIC_URL`.
- [ ] Detect Railway from `RAILWAY_ENVIRONMENT_NAME`.
- [ ] Detect Heroku from `DYNO`.
- [ ] Detect Heroku from `HEROKU_APP_NAME`.
- [ ] Detect DigitalOcean from `DO_DEPLOYMENT_ID`.
- [ ] Detect DigitalOcean from `DO_APP_NAME`.
- [ ] Detect DigitalOcean from `DIGITALOCEAN`.
- [ ] Detect Koyeb from `KOYEB`.
- [ ] Detect Koyeb from `KOYEB_DEPLOYMENT_ID`.
- [ ] Detect Koyeb from `KOYEB_APP_NAME`.
- [ ] Return null/none when no deployment vendor is detected.

### System Info

Default upstream build cannot read host system details; Node build can. Rust server implementation can safely provide host details when supported.

- [ ] Include `deploymentVendor`.
- [x] Include `systemPlatform`.
- [ ] Include `systemRelease`.
- [x] Include `systemArchitecture`.
- [x] Include `cpuCount`.
- [ ] Include `cpuModel`.
- [ ] Include `cpuSpeed` or omit with a documented null/none when unavailable.
- [ ] Include total memory when available.
- [ ] Include `isWSL`.
- [ ] Include `isDocker`.
- [x] Include `isTTY`.
- [ ] Host detection failures return null/none fields rather than errors.
- [ ] Docker detector checks `/.dockerenv` where supported.
- [ ] Docker detector checks `/proc/self/cgroup` for Docker where supported.
- [ ] Docker detector caches the result where appropriate.
- [ ] Container detector checks `/run/.containerenv` where supported.
- [ ] WSL detector returns false on non-Linux platforms.
- [ ] WSL detector checks OS release for `microsoft`.
- [ ] WSL detector checks `/proc/version` for `microsoft` where supported.
- [ ] WSL detector returns false inside containers.

### Database Detection

Upstream JS package detection maps dependency names to database names. For Rust, prefer configured OpenAuth adapter/database information, but preserve the same normalized names when possible.

- [x] Detect PostgreSQL as `postgresql`.
- [ ] Detect MySQL as `mysql`.
- [ ] Detect MariaDB as `mariadb`.
- [ ] Detect SQLite as `sqlite`.
- [ ] Detect Prisma-equivalent integrations only if a Rust project explicitly supports them.
- [ ] Detect MongoDB as `mongodb` when supported.
- [ ] Detect Drizzle-equivalent integrations only if a Rust project explicitly supports them.
- [x] Return version when the adapter/database crate version is safely available.
- [ ] Return none when no database can be detected.
- [ ] Prefer explicit telemetry context `database` over filesystem/package probing.

### Framework Detection

Upstream maps JS packages to framework names. For Rust, use explicit integration metadata or Cargo feature metadata rather than scanning JavaScript dependencies.

- [ ] Detect Next.js only for projects that intentionally expose JS host metadata.
- [ ] Detect Nuxt only for projects that intentionally expose JS host metadata.
- [ ] Detect React Router only for projects that intentionally expose JS host metadata.
- [ ] Detect Astro only for projects that intentionally expose JS host metadata.
- [ ] Detect SvelteKit only for projects that intentionally expose JS host metadata.
- [ ] Detect Solid Start only for projects that intentionally expose JS host metadata.
- [ ] Detect TanStack Start only for projects that intentionally expose JS host metadata.
- [ ] Detect Hono only for projects that intentionally expose JS host metadata.
- [ ] Detect Express only for projects that intentionally expose JS host metadata.
- [ ] Detect Elysia only for projects that intentionally expose JS host metadata.
- [ ] Detect Expo only for projects that intentionally expose JS host metadata.
- [x] Detect Rust web framework metadata when OpenAuth integration crates provide it.
- [x] Return version when safely available.
- [x] Return none when no framework can be detected.

### Package Manager Or Build Tool

- [ ] Upstream `npm_config_user_agent` parsing behavior is documented as JS-specific.
- [x] Parse a package manager user agent only when the target project deliberately exposes one.
- [ ] Normalize `npminstall` to `cnpm` if JS user agent parsing is supported.
- [x] For Rust-first projects, record Cargo version or build-tool metadata only when safely available.
- [ ] Return none when package-manager/build-tool metadata is unavailable.

## Project ID And Utilities Checklist

- [ ] Project id is cached after first generation.
- [ ] If project name is available, hash project name.
- [ ] If project name and base URL are available, hash `baseUrl + projectName` equivalent.
- [ ] If project name is unavailable but base URL is available, hash base URL.
- [ ] If neither project name nor base URL is available, generate a random 32-character id.
- [ ] Hash uses SHA-256.
- [ ] Hash output is base64 encoded.
- [ ] Random id uses uppercase letters.
- [ ] Random id uses lowercase letters.
- [ ] Random id uses digits.
- [ ] Random fallback is generated without panics.
- [ ] Project id generation does not publish the raw project name.
- [ ] Project id generation does not publish the raw base URL.
- [ ] File/package metadata readers fail closed and return none on missing files or parse errors.

## Node-Specific Upstream Behavior To Translate Carefully

These are server-side behaviors in upstream but tied to Node implementation details. Rust ports should preserve the purpose, not the exact mechanism.

- [ ] Default package-json utility returns no package version in non-Node build.
- [ ] Node package-json reader caches root `package.json`.
- [ ] Node package version lookup first checks cached dependency maps.
- [ ] Node package version lookup can inspect `node_modules/<pkg>/package.json`.
- [ ] Node package version lookup falls back to root dependency declarations.
- [ ] Node project name lookup reads root `package.json` name.
- [ ] Node-specific `createTelemetry` uses Node database detector override.
- [ ] Node-specific `createTelemetry` uses Node framework detector override.
- [ ] Rust implementation avoids reading JavaScript `package.json` unless explicitly supporting a JS host project.
- [ ] Rust implementation uses typed Rust project metadata or explicit integration context where possible.

## Test Checklist

Adapt upstream tests into Rust tests with mocked transport, mocked env, and deterministic detectors.

### Publisher Tests

- [x] Test publishes init event when telemetry is enabled by options.
- [ ] Test publishes init event when telemetry is enabled by environment.
- [x] Test does not publish when telemetry is disabled and env does not enable it.
- [x] Test `BETTER_AUTH_TELEMETRY=false` does not enable telemetry by itself. OpenAuth coverage uses the Rust env equivalent, `OPENAUTH_TELEMETRY=false`.
- [ ] Test no publish occurs in test mode unless `skipTestCheck` is set.
- [x] Test custom track receives init event when enabled.
- [x] Test custom track error is swallowed and logged.
- [x] Test missing endpoint and missing custom track returns no-op publisher.
- [x] Test no-op publisher does not call HTTP transport.
- [ ] Test endpoint transport sends POST when enabled and debug is false.
- [ ] Test debug mode logs and does not call HTTP transport.
- [ ] Test later `publish` sends caller event type and payload.
- [ ] Test later `publish` includes cached anonymous id.
- [ ] Test later `publish` is ignored when disabled.

### Init Payload Tests

- [x] Test init payload includes config snapshot.
- [x] Test init payload includes runtime detection.
- [x] Test init payload includes database detection.
- [x] Test init payload includes framework detection.
- [x] Test init payload includes environment detection.
- [ ] Test init payload includes system info detection.
- [x] Test init payload includes package manager/build tool detection when available.
- [ ] Test base URL is not present in payload.
- [ ] Test app name is not present in payload.
- [ ] Test cookie prefix value is not present in payload.
- [ ] Test cross-subdomain cookie domain value is not present in payload.
- [ ] Test callbacks are represented as booleans.
- [ ] Test provider secrets are not serialized.

### Auth Config Snapshot Tests

- [ ] Test empty options produce default false/none snapshot values.
- [ ] Test email verification flags and durations map correctly.
- [ ] Test email/password flags and password callback presence map correctly.
- [ ] Test social provider list maps provider ids and safe capability flags.
- [ ] Test lazy provider config is resolved before snapshotting.
- [ ] Test plugin ids are collected as strings.
- [ ] Test user, verification, session, and account model metadata maps correctly.
- [ ] Test hooks and database hooks map to boolean presence.
- [ ] Test advanced cookie fields sanitize actual values.
- [ ] Test trusted origins are represented as count.
- [ ] Test rate limit metadata maps correctly.
- [ ] Test API error and logger metadata maps correctly.

### Detector Tests

- [ ] Test environment returns production when production env is set.
- [ ] Test environment returns ci for CI env when production is not set.
- [ ] Test environment returns test under test mode when production and CI are absent.
- [ ] Test environment returns development as fallback.
- [ ] Test CI detector handles each supported CI env key.
- [ ] Test CI detector returns false when `CI=false`.
- [ ] Test each deployment vendor env key maps to the expected vendor name.
- [ ] Test no deployment vendor returns none.
- [ ] Test system detector returns null/none fields when host APIs fail.
- [ ] Test Docker detector handles `/.dockerenv` present.
- [ ] Test Docker detector handles `/proc/self/cgroup` containing Docker.
- [ ] Test WSL detector returns false inside container.
- [x] Test database detector maps supported databases to normalized names.
- [ ] Test database detector returns none when no database is configured.
- [x] Test framework detector maps supported integration metadata to normalized names.
- [x] Test framework detector returns none when no framework is configured.
- [x] Test package manager/build tool detector parses known metadata.
- [ ] Test package manager/build tool detector returns none when metadata is missing.

### Project ID Tests

- [ ] Test project name only produces stable SHA-256 base64 id.
- [ ] Test base URL plus project name produces a different stable id from project name only.
- [ ] Test base URL only produces stable SHA-256 base64 id.
- [ ] Test missing base URL and project name produces a 32-character random id.
- [ ] Test generated random id uses only letters and digits.
- [ ] Test project id is cached after first call.
- [ ] Test metadata reader errors produce fallback behavior.

## Documentation Checklist

- [ ] Document telemetry as anonymous, opt-in usage analytics.
- [ ] Document that telemetry is disabled by default.
- [ ] Document enablement through options.
- [ ] Document enablement through environment variable.
- [ ] Document debug behavior.
- [ ] Document endpoint behavior.
- [ ] Document custom track behavior.
- [ ] Document all data categories included in the init event.
- [ ] Document all sensitive categories intentionally excluded.
- [ ] Document how to disable telemetry in tests and CI.
- [ ] Document how host/runtime/database/framework detection works in Rust projects.
- [ ] Document that CLI telemetry events are accepted by the generic publisher only when the target project ships CLI tooling.
- [ ] Document that anonymous usage telemetry is separate from OpenTelemetry tracing/instrumentation.

## Privacy And Security Review Checklist

- [ ] Review every serialized field for secrets before release.
- [ ] Confirm no raw base URL is serialized.
- [ ] Confirm no raw project name is serialized.
- [ ] Confirm no cookie names or cookie values are serialized.
- [ ] Confirm no cookie domain values are serialized.
- [ ] Confirm no trusted origin values are serialized.
- [ ] Confirm no OAuth provider credentials are serialized.
- [ ] Confirm no OAuth tokens are serialized.
- [ ] Confirm no session identifiers are serialized.
- [ ] Confirm no user identifiers or emails are serialized.
- [ ] Confirm no verification token values are serialized.
- [ ] Confirm no callback function bodies or debug representations are serialized.
- [ ] Confirm HTTP/custom-track failures are non-fatal.
- [ ] Confirm telemetry transport can be disabled entirely.

## Upstream Test Cases Captured

From `src/telemetry.test.ts`:

- [x] `publishes events when enabled`
- [x] `does not publish when disabled via env`
- [x] `does not publish when disabled via option`
- [x] `shouldn't fail cause track isn't being reached`
- [x] `initializes without Node built-ins in edge-like env`
- [x] `returns noop publisher when BETTER_AUTH_TELEMETRY_ENDPOINT is undefined` (covered with OpenAuth's `OPENAUTH_TELEMETRY_ENDPOINT` equivalent).

## Self-Review

- [ ] Source coverage checked against every file in `packages/telemetry/src`.
- [ ] Public API, config snapshot, detectors, utilities, transport, and tests are all represented.
- [ ] Browser-only/client behavior excluded.
- [ ] TypeScript-only packaging details documented as non-goals or translation notes.
- [ ] No current OpenAuth implementation was used to mark completion.
