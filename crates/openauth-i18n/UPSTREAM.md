# Upstream parity — openauth-i18n

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
OpenAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/i18n` |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/i18n/` |
| **Rust crate** | `crates/openauth-i18n/` |
| **Parity level** | **~99%** (server plugin) |
| **Scope** | Server plugin only: error-message translation via response hook. No HTTP routes, DB schema, migrations, adapters, or rate limits. Re-exported from `openauth` with feature `i18n`. |
| **Audit status** | **Complete (server-only, 2026-06-07)** |

### Upstream server files (audited)

| File | Role |
| --- | --- |
| `src/index.ts` | Plugin constructor, `detectLocale`, `parseAcceptLanguage`, `hooks.after` translation |
| `src/types.ts` | `I18nOptions`, `LocaleDetectionStrategy`, `TranslationDictionary` |
| `src/version.ts` | Plugin version metadata (`PACKAGE_VERSION`) |
| `src/i18n.test.ts` | Vitest scenarios (sign-in errors, detection, fallback) |
| `docs/content/docs/plugins/i18n.mdx` | Documented server contract (options, detection, response shape) |

Supplementary integration references (audited): `packages/core/src/utils/is-api-error.ts`
(error gate), `packages/better-auth/src/cookies/index.ts` `parseCookies` (cookie parsing contract).

Excluded from audit (not server runtime): `src/client.ts`, `tsconfig.json`, `tsdown.config.ts`,
`vitest.config.ts`, `package.json` `./client` export.

## Summary

OpenAuth mirrors the upstream i18n server contract: on error responses, detect a locale,
look up `code` in the translation dictionary, replace `message`, and set `originalMessage`.
The plugin owns no routes—it hooks `on_response` after handlers and router early exits
(`openauth-core` `finalize_response` / `finalize_response_async`). Rust adds explicit config
validation, case-insensitive locale catalogs, richer `Accept-Language` matching, typed error-code
keys, optional `resolve_user_locale`, async session user hydration before the hook on the
async router path, and async `get_locale_async` callbacks via `on_response_async`.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin id `i18n` + version metadata | ✅ | `AuthPlugin::with_version`, `with_options` JSON |
| Error translation (`code` → `message`, `originalMessage`) | ✅ | Skips success, non-JSON, empty/missing `code`, unknown codes |
| Locale detection (`header`, `cookie`, `session`, `callback`) | ✅ | Same strategy order and defaults (`locale` cookie/field) |
| `Accept-Language` parsing | ✅ | Quality ordering; exact region before base fallback |
| Default locale resolution | ✅ | `en` → first key; explicit `defaultLocale` validated at build |
| No endpoints / schema / migrations | ✅ | Plugin-only surface |
| Router early exits (404, rate limit, `INVALID_ORIGIN`) | 🎯 | `finalize_response(_async)` runs `on_response` hooks |
| Session locale from DB | 🎯 | `ensure_session_user_in_request_state` + optional `resolve_user_locale` |
| Async `getLocale` callback | ✅ | `get_locale_async` on `AuthRouter::handle_async` via `on_response_async` |
| `isAPIError` gate before translate | 🎯 | OpenAuth uses status + JSON `code` on `on_response` (broader, still skips success) |

## Test coverage

| Surface | OpenAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Integration scenarios | 50 | 15 `it()` | `tests/i18n.rs` ↔ `src/i18n.test.ts` |
| Unit tests (`src/`) | 16 | — | `accept_language`, `locale`, `cookie`, `response` |
| Test harness | `tests/common/mod.rs` | `better-auth/test` | In-memory adapter + async router |
| **Total** | **66** | **15** | Rust superset: config validation, early exits, hydration, content-type gates |

```bash
cargo nextest run -p openauth-i18n
```

Cross-crate: `openauth-core` session hydration (`session_request_state.rs`) is covered by
`session_detection_reads_locale_from_session_cookie_hydration`. Facade re-export tested in
`openauth` `public_api.rs` (`i18n` feature).

## Intentional differences

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| Plugin construction | Throws on empty `translations`; silent invalid `defaultLocale` fallback | `Result<AuthPlugin, I18nConfigError>` | Explicit errors at build time |
| Locale key matching | Exact dictionary keys | Case-insensitive catalog; rejects duplicates after normalization | Safer configuration |
| `Accept-Language` | Strips to base language in parser (`fr-CA` → `fr`) | Keeps full tags; exact region before base fallback | Finer control when both `pt` and `pt-BR` exist |
| Error translation gate | `isAPIError(returned)` in `hooks.after` | Non-success `application/json` with string `code` on `on_response` | Typed pipeline; also covers router/plugin short-circuits |
| `getLocale` | May return `Promise` | `get_locale` sync; `get_locale_async` on async router paths | Sync `AuthRouter::handle` keeps sync callbacks only |
| Error code keys | String dictionary keys | `translation_dictionary` + `ApiErrorCode` / `AuthFlowErrorCode` | Compile-time keys without bundling translations |
| Session locale | Reads `ctx.context.session.user` field synchronously | `resolve_user_locale` + async cookie hydration on `handle_async` | DB-backed sessions in OpenAuth |
| Translation mechanism | Throws new `APIError` | Mutates response body in place | Same observable JSON contract |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G2 | Session detection on sync `handle()` | ➖ | Intentional: sync router cannot hydrate DB sessions; use `handle_async`, `resolve_user_locale`, or pre-set request state |
| G3 | Fail-open missing translations | ➖ | Intentional (matches upstream): unknown `code` leaves original `message`; operators must cover exposed codes |
| G4 | `application/json` gate only | ➖ | Intentional: server JSON API errors only; HTML/plain-text pages are out of scope |
| G5 | Broader translate gate vs `isAPIError` | 🎯 | OpenAuth extension: non-`ApiErrorResponse` JSON errors with `code` translate on `on_response` |

## Hardening notes

- Stateless plugin; safe for multi-instance deployments.
- Translation is fail-open on missing keys—operators must maintain complete dictionaries.
- `Content-Length` removed when the body is rewritten (tested).
- Success and non-JSON responses are never modified.
- `originalMessage` preserves the prior public `message` only (no internal error leakage).

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `packages/i18n/src/` and `docs/content/docs/plugins/i18n.mdx`.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `src/index.ts` (`i18n`, `detectLocale`, `parseAcceptLanguage`, `hooks.after`) | `src/plugin.rs`, `src/accept_language.rs` |
| `src/types.ts` | `src/types.rs` |
| `better-auth/cookies` `parseCookies` | `src/cookie.rs` (`openauth-core::cookies`) |
| `APIError` rewrite | `src/response.rs` (`translate_response`) |
| Locale catalog / matching | `src/locale.rs` |
| Config validation | `src/error.rs` |
| `finalize_response_async` session hydration | `openauth-core/src/api/session_request_state.rs` |
| `on_response_async` (async locale pre-detection) | `openauth-core/src/api/plugin_pipeline.rs` |
| `src/i18n.test.ts` | `tests/i18n.rs`, `tests/common/mod.rs` |

5. Add a failing Rust test before behavior changes; match JSON shape, locale selection,
   status code, and `originalMessage`.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
- [Server checklist](../../docs/superpowers/plans/2026-05-12-upstream-i18n-server-checklist.md) — detailed porting checklist (reference)
