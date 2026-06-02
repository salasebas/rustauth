# Divergences, scope, and decisions

## Out of scope (N/A — client / TypeScript)

OpenAuth is **server-only**. The following will not be ported:

| Upstream capability | File | Reason |
| --- | --- | --- |
| `passkeyClient()` | `client.ts` | Better Auth client + nanostores |
| `getPasskeyActions`, `signIn.passkey`, `passkey.addPasskey` | `client.ts` | Browser orchestration |
| `startRegistration` / `startAuthentication` | `@simplewebauthn/browser` | Browser only |
| `useBrowserAutofill` (conditional UI) | client | Integrator uses native WebAuthn |
| Cache `$listPasskeys`, `$sessionSignal` | client | Client state |
| `WebAuthnError` → `REGISTRATION_CANCELLED` / etc. | client | Browser UX errors |
| Tests `client.test.ts` | — | 2 cases not applicable |

The upstream server **does not** implement `/passkey/register` or `/passkey/authenticate` client hints; OpenAuth does not need them either.

## Intentional server design decisions

| Topic | Upstream | OpenAuth | Why |
| --- | --- | --- | --- |
| Table / columns | Model `passkey`, camelCase in adapter | Default table `passkeys`, snake_case DB, camelCase JSON API | Rust/SQL and OpenAuth adapter conventions |
| WebAuthn persistence | Schema fields only; auth verify rebuilds from `publicKey` | Hidden `webauthn_credential` JSON field | `webauthn-rs` needs full credential state for secure verify and counter/backup updates |
| Ceremony state | JSON with `expectedChallenge` + userData | Serialized `RegistrationState` / `AuthenticationState` | `danger-allow-state-serialisation`; do not trust the client |
| Crypto stack | SimpleWebAuthn | `webauthn-rs` | Idiomatic Rust ecosystem |
| Injectable backend | No | `PasskeyWebAuthnBackend` | Tests without global crate mocks |
| Unique `credential_id` | Index only | UNIQUE + PG/MySQL/SQLite tests | Avoid duplicate credentials and races |
| Auth verify with prior session | Lookup by `credentialID` only | If challenge was created with a session, passkey must belong to that `user.id` | Hardening: blocks using session A allowCredentials with user B’s valid credential |
| User verification policy | `requireUserVerification: false` fixed on verify | Policy consistent between generated options and verify (OPE-48 tests) | Fix advertise vs verify mismatch |
| Loopback origins | Library / single origin | Explicit port rules for loopback vs prod | Local DX without relaxing production |
| Errors | Broad `try/catch` → `FAILED_TO_VERIFY_*` | `Result` + explicit codes on critical routes | Rust idiom; security boundaries preserved |
| `origin` in options | `null` = use header | Empty `Vec` = header/base_url | Rust type without null |
| Update/delete 404 | Generic throw on some paths | Documented `PASSKEY_NOT_FOUND` | Clear API contract |

## Aligned with upstream (server checklist)

- [x] 7 endpoints same path and method
- [x] Plugin id `passkey`
- [x] Challenge cookie `better-auth-passkey`, 5 minutes
- [x] `requireSession` / `resolveUser` / `context` / extensions
- [x] Fresh session on registration (default)
- [x] Discoverable auth without session
- [x] `afterVerification` registration (userId override pre-auth) and auth (hook)
- [x] `credentialID` in public JSON
- [x] `publicKey` as base64 COSE CBOR
- [x] Random WebAuthn user handle per registration (not DB id in ceremony)
- [x] AAGUID from attestation when metadata exists
- [x] Ownership update vs delete (distinct codes)
- [x] GHSA cross-user update/delete
- [x] Session + user on verify-authentication

## OpenAuth extensions (not in upstream passkey package)

| Extension | Benefit |
| --- | --- |
| Multi-DB migration tests | Production schema contract |
| OpenAPI body schemas | HTTP documentation / codegen |
| Secondary storage tests | Redis-like deployment parity |
| Cookie prefix / cross-subdomain | `openauth-core` cookie parity |
| Many invalid/expired/reused challenge tests | Security regression |
| Real `webauthn-rs` in CI | Not mocks only |
| Session IP from trusted resolver | Anti-spoofing |

## Gaps / optional follow-up

| Item | Type | Priority |
| --- | --- | --- |
| `options.schema` / `mergeSchema` (rename fields, extra fields) | Server gap | Medium — main remaining functional gap |
| ~~Auth extensions without `user_id`~~ | `PasskeyExtensionsInput::user_id` | Closed |
| ~~Legacy `excludeCredentials`~~ | `registration_exclude_value` + parser | Closed |
| ~~Pre-auth `displayName` test~~ | `generate_register_options_uses_resolve_user_display_name` | Closed |
| Explicit test for `afterVerification` with non-string userId | N/A Rust | — |
| ~~HTTP 500 vs 400 on verify-registration / user-not-found verify-auth~~ | Aligned 500 with upstream | Closed |
| ~~`SESSION_NOT_FRESH` HTTP status~~ | Aligned 403 | Closed |
| ~~`list-user-passkeys` Set-Cookie~~ | Aligned (no cookies) | Closed |
| `anonymous` / `last-login-method` plugins depend on verify-auth | Ecosystem | Info ([09 §1](./09-ecosystem-and-edge-cases.md)) |
| `deviceType`: SimpleWebAuthn `credentialDeviceType` vs `backup_eligible` | Mapping nuance | Low |
| Document HTTP flow without TS client | Docs | Medium |
| `REGISTRATION_CANCELLED` / `AUTH_CANCELLED` registry only | Aligned upstream | None |

## Parity estimate

| Area | Estimated % |
| --- | ---: |
| Endpoints and HTTP JSON contract | ~100% |
| Server configuration options | ~98% |
| Public schema | ~100% |
| Observable cryptographic behavior | ~95% (different stack, same results in tests) |
| Equivalent upstream server tests | >100% (more coverage) |
| **Overall server** | **~99%** |

Optional ~1% remainder: `mergeSchema` (column renames), verify-auth with `publicKey` only and no `webauthn_credential` (legacy Better Auth migrations), and OpenAPI/client details — see **When to stop** below.

## When to stop (recommendation)

**No further work** is warranted for “observable server parity” unless you have explicit product requirements:

| Remaining work | Effort | Value |
| --- | --- | --- |
| `options.schema` / `mergeSchema` | High (cross-plugin API + adapters) | Low unless deployments rename columns |
| Rebuild credential from `publicKey` on verify-auth | High (inverse COSE → `webauthn-rs` `Passkey`) | Only legacy rows without `webauthn_credential` |
| TS client / SimpleWebAuthn browser | Out of scope | N/A |

Closed in the latest iteration: `SESSION_NOT_FRESH` **403**, verify errors **500** aligned, legacy `excludeCredentials`/`allowCredentials`, `user_id` in auth extensions, `list-user-passkeys` without cookies.

## Maintenance

On Better Auth version bump in `reference/upstream-better-auth/VERSION.md`:

1. Re-diff `packages/passkey/src/routes.ts`, `schema.ts`, `types.ts`, `passkey.test.ts`
2. Update tables in this folder
3. Sync `crates/openauth-passkey/UPSTREAM_PARITY.md` with the summary in [README.md](./README.md)
