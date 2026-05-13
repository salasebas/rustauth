# Upstream i18n Server Checklist Implementation Plan

> **Guide note:** This document is a coverage guide, not a requirement to copy Better Auth line by line. If the target Rust implementation adds behavior that covers the same user-facing/server-side responsibility more correctly, more securely, or more idiomatically, mark the corresponding checklist item as complete and document the improved behavior.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Coverage pass 2026-05-12:** Checked against `crates/openauth-i18n` and its focused tests. Completed boxes below mean the behavior is implemented and either directly tested or explicitly reviewed in code where the item is a surface-absence assertion.

**Goal:** Build a reusable server-side checklist for porting the Better Auth `@better-auth/i18n` package behavior into an idiomatic Rust authentication project.

**Architecture:** Treat i18n as a server plugin/hook that post-processes API errors after endpoint execution. Locale detection is configured by ordered strategies, and translated errors preserve the original machine-readable error code and original message.

**Tech Stack:** Rust auth core/plugin system, HTTP headers, cookie parsing, session context access, async callback support, typed API errors, focused Rust tests.

---

## Scope

Upstream source inspected:

- `upstream/better-auth/1.6.9/repository/packages/i18n/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/i18n/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/i18n/src/i18n.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/i18n/src/client.ts`
- `upstream/better-auth/1.6.9/repository/packages/i18n/src/version.ts`
- `upstream/better-auth/1.6.9/repository/packages/i18n/package.json`
- `upstream/better-auth/1.6.9/repository/packages/i18n/README.md`
- `upstream/better-auth/1.6.9/repository/packages/i18n/CHANGELOG.md`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/plugins/i18n.mdx`
- `upstream/better-auth/1.6.9/repository/packages/cli/src/commands/init/configs/temp-plugins.config.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/api/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/error/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/types/plugin.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/utils/is-api-error.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/cookies/index.ts`

This checklist intentionally does not inspect the current OpenAuth implementation. Mark items complete only after comparing against the target project during a later implementation/review phase.

Server-side only:

- Include the server plugin, error translation behavior, locale detection, configuration types, error-code translation contracts, and tests.
- Exclude the Better Auth client plugin except as a future thin client typing/SDK compatibility note.
- Exclude TypeScript build tooling details unless they imply package exports or dependency behavior.
- Do not create auth endpoints for this plugin: upstream `i18n` has no `endpoints`, no `createAuthEndpoint`, and no OpenAPI metadata.
- Do not create database schema, migrations, adapters, or rate-limit rules for this plugin: upstream `i18n` has none.

## Upstream Dependency Map

- [x] `@better-auth/core`: plugin contract, endpoint context, plugin registry, and type-level error-code aggregation. Rust equivalent should be the target auth core's plugin/hook/context traits.
- [x] `better-auth/api`: `APIError`, `createAuthMiddleware`, and `isAPIError`. Rust equivalent should be the target project's typed API error type plus after-response/error hook integration.
- [x] `better-call`: transitive runtime behind Better Auth endpoints/middleware and base `APIError`. Rust equivalent should be the existing HTTP endpoint/middleware abstraction, not a new i18n-specific dependency.
- [x] `createAuthMiddleware`: supplies auth context plus post-hook fields such as `ctx.context.returned` and `ctx.context.responseHeaders`. Rust equivalent must expose the endpoint result/error to after hooks.
- [x] `isAPIError`: treats Better Auth API errors as API errors when they are an instance of the base error, an instance of Better Auth `APIError`, or have name `APIError`. Rust equivalent should use typed errors instead of name-string detection.
- [x] `APIError`: wraps status plus body fields such as `code` and `message`; i18n constructs a new API error with the same status, same code, translated message, and `originalMessage`.
- [x] `better-auth/cookies`: `parseCookies`. Upstream splits the `Cookie` header on `"; "` and splits each cookie on the first `=`, preserving values that contain `=`; it does not percent-decode or strongly validate cookies.
- [x] Rust cookie parsing equivalent: use an existing project parser if present; if none exists, propose a small dependency such as `cookie` before adding it.
- [x] `package.json` import in `version.ts`: package version export. Rust equivalent can use workspace crate version metadata if exposed through plugin metadata.
- [x] `vitest` and `better-auth/test`: upstream test harness only. Rust equivalent should be crate tests/unit tests using the target project's HTTP/API test harness.
- [x] `tsdown`, `publint`, `attw`, TypeScript config: build/package tooling only; no server runtime behavior to port.

## Package Surface Checklist

### Public Server API

- [x] Provide an `i18n` server plugin/constructor.
- [x] Expose plugin id as `i18n`.
- [x] Expose plugin version metadata if the target plugin interface supports versions.
- [x] Export/re-export i18n option types from the server package/crate.
- [x] Register i18n with the auth plugin registry if the target system has plugin discovery/registration.
- [x] Preserve the concept that translations are supplied by the application, not bundled by the plugin.
- [x] Support arbitrary translation keys so project/plugin-specific error codes can be translated.
- [x] Prefer typed known error-code keys where the target Rust API can model them cleanly.

### No Endpoint Or Storage Surface

- [x] Confirm the plugin exposes no auth endpoints.
- [x] Confirm no `createAuthEndpoint` equivalent is needed.
- [x] Confirm no OpenAPI route metadata is needed because the plugin does not add routes.
- [x] Confirm no database tables are required.
- [x] Confirm no migrations are required.
- [x] Confirm no adapter methods are required.
- [x] Confirm no rate-limit rules are required.
- [ ] Confirm no `onRequest`/`onResponse` top-level plugin hooks are required; upstream uses `hooks.after`.

### Excluded Client API

- [x] Do not port `i18nClient` into the Rust core server implementation.
- [x] Record future SDK/client work separately: Better Auth's client plugin only provides client-side type inference and does not translate messages on the client.
- [x] Do not port TypeScript module augmentation into Rust.

## Suggested Modularization Checklist

Use the target project's naming conventions when implementing. The important requirement is separation of responsibilities, not these exact filenames.

- [x] Keep public exports and plugin constructor small, e.g. `lib.rs` or `plugin.rs`.
- [x] Keep option/data types separate from hook logic, e.g. `types.rs`.
- [x] Keep `Accept-Language` parsing isolated, e.g. `accept_language.rs`, with direct unit tests.
- [x] Keep locale detection strategy orchestration isolated, e.g. `detection.rs`, if it grows beyond simple plugin-local functions.
- [x] Keep API error translation logic isolated from locale detection, e.g. `error.rs` or `translator.rs`.
- [x] Keep cookie parsing integration behind a small helper if the project does not already expose one, e.g. `cookie.rs`.
- [x] Keep tests grouped by behavior: header detection, cookie detection, session detection, callback detection, fallback validation, and error response shape.
- [x] Do not put route/endpoint files under i18n unless later behavior actually adds routes; upstream i18n does not.

## Types And Configuration Checklist

### Translation Dictionary

- [x] Model a translation dictionary as locale code -> error code -> translated message.
- [x] Allow partial dictionaries: locales do not need translations for every error code.
- [x] Allow custom error-code strings beyond first-party auth errors.
- [x] Store translated messages as strings.
- [x] Reject an empty translations map during plugin construction/config validation.

### Locale Detection Strategy

- [x] Define supported strategies: `header`, `cookie`, `session`, `callback`.
- [x] Preserve ordered strategy priority: the first strategy that returns an available locale wins.
- [x] Default detection strategy to `["header"]`.
- [x] Ensure invalid/unsupported strategy values are rejected at config boundaries if externally deserialized.
- [x] Preserve the distinction between "detected but unsupported locale" and "no locale detected": both should continue to the next strategy or fallback rather than producing an error.

### Plugin Options

- [x] `translations`: required map of configured locales to dictionaries.
- [x] `defaultLocale`: optional configured fallback locale.
- [x] `detection`: optional ordered list of detection strategies.
- [x] `localeCookie`: optional cookie name for cookie detection.
- [x] `userLocaleField`: optional session user field name for session detection.
- [x] `getLocale`: optional custom locale callback for callback detection.
- [x] Default `localeCookie` to `locale`.
- [x] Default `userLocaleField` to `locale`.
- [x] Validate that a configured `defaultLocale` is only used when it exists in `translations`.
- [x] Store resolved options in plugin metadata/options if the target plugin system exposes configured plugin options.

### Default Locale Resolution

- [x] If `defaultLocale` is provided and exists in `translations`, use it.
- [x] Else, if locale `en` exists in `translations`, use `en`.
- [x] Else, if at least one locale exists, use the first configured locale.
- [x] Else, fail plugin construction with a clear configuration error.

## Locale Parsing And Detection Checklist

### Accept-Language Parsing

- [x] Return no candidates when the `Accept-Language` header is absent.
- [x] Split header values by comma.
- [x] Parse optional `q=` quality values.
- [x] Treat entries without `q=` as quality `1`.
- [x] Sort candidates by descending quality.
- [x] Extract the base locale by splitting on `-`, e.g. `fr-CA` becomes `fr`.
- [x] Ignore empty locale entries.
- [x] Return locale candidates in priority order.
- [x] Match candidates only against locales configured in `translations`.
- [x] Add a deliberate Rust decision for malformed `q=` values: either preserve upstream's loose behavior or normalize invalid values predictably in tests.

### Header Strategy

- [x] Read `Accept-Language` from request headers.
- [x] Parse candidate locales using the Accept-Language parser.
- [x] Use the first parsed candidate that exists in `translations`.
- [x] Return no locale from this strategy when no candidate is configured.

### Cookie Strategy

- [x] Read the raw `Cookie` header.
- [x] Parse cookies with a real cookie parser rather than ad hoc splitting if the project has one.
- [x] Preserve support for cookie values containing `=` if using a custom parser.
- [x] Read the cookie named by `localeCookie`.
- [x] Use the cookie locale only if it exists in `translations`.
- [x] Return no locale when the cookie is absent, malformed, or unsupported.

### Session Strategy

- [x] Access the current session user from endpoint context.
- [x] Read the configured `userLocaleField` from the user/session representation.
- [x] Use the session locale only if it is a string and exists in `translations`.
- [x] Return no locale when there is no session, no user, no configured field, or an unsupported locale.

### Callback Strategy

- [x] Call `getLocale` only when callback detection is configured and a callback is provided.
- [ ] Support async callback behavior.
- [x] Pass endpoint context into the callback.
- [x] Allow callbacks to return a locale or `null`/none.
- [x] Use the callback locale only if it exists in `translations`.
- [ ] Ensure callback detection works even when there is no concrete HTTP request object in context.

### Detection Fallback

- [x] Run strategies exactly in configured order.
- [x] Stop at the first strategy that returns a supported locale.
- [x] Fall back to resolved `defaultLocale` when no strategy returns a supported locale.

## Error Translation Hook Checklist

### Hook Registration

- [x] Register an after-endpoint hook/middleware.
- [x] Match all endpoints/routes.
- [x] Run after the endpoint has produced a returned value.
- [x] Inspect only the returned value/error, not successful responses.
- [x] Ensure the after hook has access to the endpoint's returned error/result equivalent, matching Better Auth's `ctx.context.returned`.

### API Error Recognition

- [x] Detect target-project API errors reliably.
- [x] Ignore non-error responses.
- [x] Ignore errors that do not expose a string machine-readable `code`.
- [x] Preserve the original HTTP status.
- [x] Preserve the original error code.
- [x] Avoid stringly typed error recognition in Rust where a typed enum/struct can represent API errors.

### Translation Behavior

- [x] Detect locale for the current request/context.
- [x] Look up `translations[locale][errorCode]`.
- [x] When a translation exists, replace the response error message with the translated message.
- [x] Include the original message as `originalMessage` in the error body/metadata when translating.
- [x] When no translation exists for that locale/error code, leave the original error unchanged.
- [x] When detected locale is unsupported, use the resolved default locale.
- [x] When default locale also has no translation for the error code, leave the original error unchanged.
- [x] Do not translate successful responses.

### Error Response Shape

- [x] Translated error responses include `code`.
- [x] Translated error responses include translated `message`.
- [x] Translated error responses include `originalMessage`.
- [x] Status code remains the same as the original API error.
- [x] Avoid leaking sensitive internal error details through `originalMessage`; only preserve the public message that would have been returned.
- [x] Preserve any response headers attached to the original API error if the target error pipeline supports error headers.

## Tests Checklist

### Header Detection Tests

- [x] Translates an email/password API error to French when `Accept-Language: fr`.
- [x] Translates the same error to German when `Accept-Language: de`.
- [x] Uses fallback/default behavior when `Accept-Language` is an unsupported locale such as `es`.
- [x] Honors `q=` quality ordering, e.g. `es;q=0.9, fr;q=0.8, en;q=0.7` resolves to `fr` when `es` is unsupported.
- [x] Extracts base locale from a full locale code, e.g. `fr-CA` resolves to `fr`.
- [x] Unit-tests the parser separately if it is implemented outside the hook.
- [x] Covers absent `Accept-Language` header with default locale fallback.
- [x] Covers malformed or unusual `Accept-Language` segments if the Rust implementation intentionally improves upstream parser behavior.

### Cookie Detection Tests

- [x] Uses locale from cookie when detection order is `["cookie", "header"]`.
- [x] Honors a custom `localeCookie`, e.g. `lang=fr`.
- [x] Confirms cookie priority over header when cookie appears first and header contains another supported locale.
- [x] Falls through to later strategies when the cookie locale is unsupported or missing.

### Session Detection Tests

- [x] Uses locale from the current session user when detection includes `session`.
- [x] Honors a custom `userLocaleField`.
- [x] Falls through when there is no session user.
- [x] Falls through when the session field is absent, non-string, or unsupported.

### Callback Detection Tests

- [x] Uses `getLocale` when detection is `["callback"]`.
- [x] Supports callback reading a custom header such as `X-Custom-Locale`.
- [x] Supports callback returning a locale without relying on an HTTP request object.
- [x] Falls through when callback returns none/null.
- [x] Falls through when callback returns an unsupported locale.
- [ ] Covers async callback behavior.

### Fallback And Validation Tests

- [x] Uses first configured locale when no `defaultLocale` is provided and `en` is absent.
- [x] Uses specified `defaultLocale` when it exists in `translations`.
- [x] Uses `en` when available and `defaultLocale` is not specified.
- [x] Fails construction/config validation when `translations` is empty.
- [x] Confirms configured `defaultLocale` is ignored or rejected when it is not present in `translations`, according to the Rust API decision.
- [x] Confirms default detection is `["header"]` when `detection` is omitted.
- [x] Leaves the original error unchanged when the detected locale lacks a translation for that error code.
- [x] Leaves the original error unchanged when the returned error has no string code.
- [x] Leaves non-error/success responses unchanged.

### Error Response Tests

- [x] Translated response preserves the original error `code`.
- [x] Translated response replaces `message`.
- [x] Translated response includes `originalMessage`.
- [x] Translated response preserves the original HTTP status.
- [x] Translated response preserves relevant response headers if the original API error carried headers.

### Surface Absence Tests Or Assertions

- [x] Assert or review that i18n registers no endpoints/routes.
- [x] Assert or review that i18n registers no OpenAPI metadata.
- [x] Assert or review that i18n registers no database schema/migrations.
- [x] Assert or review that i18n registers no adapter methods.

## Documentation Checklist

- [ ] Document that the plugin translates server error messages by error code.
- [ ] Document that English/default messages already come from the core error system; translations are only needed for locales the app wants to support.
- [ ] Document the translated error response shape with `code`, `message`, and `originalMessage`.
- [ ] Document detection strategy order and defaults.
- [ ] Document header, cookie, session, and callback strategies.
- [ ] Document `ctx.request`/request object may be absent for non-HTTP/internal API calls if the target project has such calls.
- [ ] Document fallback behavior: unsupported locale or missing translation keeps the original message.
- [ ] Document that client-side translation is not part of this server plugin.
- [ ] Document that the plugin does not add endpoints, tables, migrations, or OpenAPI routes.
- [ ] Document module boundaries if the implementation is split across multiple files.

## Implementation Notes For Later

- [x] Better Auth's docs describe UI strings, but the inspected package implementation translates API error messages only. Do not add UI string translation to the server core unless a later spec explicitly asks for it.
- [x] Better Auth's upstream fallback test named "translation is missing" does not strongly exercise a missing translation key because the tested German key exists. Add a direct missing-key test in the Rust implementation.
- [x] Better Auth base-locale matching only splits on `-`; it does not implement full BCP 47 negotiation. Preserve this simple behavior unless a later Rust design intentionally chooses a stronger locale matcher.
- [x] Better Auth cookie parsing is minimal. A Rust implementation may be stricter or more standards-compliant if tests document the intended behavior.
- [x] Better Auth constructs a fresh `APIError` when translating. A Rust implementation can mutate/transform an error response instead if it preserves status, code, translated message, original public message, and headers.
- [x] If a Rust dependency is needed for cookie parsing, propose it before adding it.
- [x] If a Rust dependency is considered for `Accept-Language` parsing, prefer a small explicit parser first because upstream behavior is simple and easy to test.
