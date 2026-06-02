# Package and code mapping

## 1:1 package relationship

Unlike plugins inside `packages/better-auth/`, upstream passkey is an **independent monorepo package**. OpenAuth mirrors that with an **independent crate** — no artificial split into three crates; server packaging is conceptually 1:1.

| Upstream | OpenAuth |
| --- | --- |
| npm `@better-auth/passkey` | crate `openauth-passkey` |
| export `.` (server) | `src/lib.rs`, `src/routes/*`, etc. |
| export `./client` | **Not ported** (see [07-design-differences.md](./07-design-differences.md)) |
| plugin id `"passkey"` | `UPSTREAM_PLUGIN_ID = "passkey"` |

Meta-crate integration:

| Upstream | OpenAuth |
| --- | --- |
| `plugins: [passkey()]` in `better-auth` | `OpenAuth::builder().plugin(passkey(...))` |
| — | Optional feature `openauth/passkey` → `pub use openauth_passkey as passkey` |

## File tree

### Upstream (`packages/passkey/src/`)

| File | Role |
| --- | --- |
| `index.ts` | `passkey()` factory, endpoint registration, schema merge |
| `routes.ts` | All 7 HTTP endpoints (~1086 lines) |
| `schema.ts` | DB model `passkey` |
| `types.ts` | `PasskeyOptions`, callbacks, WebAuthn types |
| `error-codes.ts` | `PASSKEY_ERROR_CODES` |
| `utils.ts` | `getRpID()` |
| `client.ts` | TS client + SimpleWebAuthn browser |
| `passkey.test.ts` | Server tests (Vitest) |
| `client.test.ts` | Client tests (Vitest) |

### OpenAuth (`crates/openauth-passkey/src/`)

| File / module | Upstream equivalent |
| --- | --- |
| `lib.rs` | `index.ts` |
| `routes.rs` + `routes/registration.rs` | Registration part of `routes.ts` |
| `routes/authentication.rs` | Auth part of `routes.ts` |
| `routes/management.rs` | list/update/delete in `routes.ts` |
| `schema.rs` | `schema.ts` |
| `options.rs` | `types.ts` (public options) |
| `errors.rs` | `error-codes.ts` |
| `store.rs` | Inline `adapter.create/findMany/...` in routes |
| `challenge.rs` | `createVerificationValue` + challenge parsing |
| `cookies.rs` | `createAuthCookie` + signed cookie |
| `session.rs` | `freshSessionMiddleware`, `getSessionFromCtx`, `createSession` |
| `webauthn.rs` | SimpleWebAuthn `generate*Options` / `verify*Response` |
| `response.rs` | `APIError` / JSON responses |
| `openapi.rs` | OpenAPI metadata on upstream routes |

**Modules without a direct upstream file:** `store`, `challenge`, `cookies`, `webauthn` (abstraction + `webauthn-rs`), dedicated `openapi`.

## Dependencies and WebAuthn stack

| Layer | Upstream | OpenAuth | Notes |
| --- | --- | --- | --- |
| Server WebAuthn | `@simplewebauthn/server` ^13 | `webauthn-rs` 0.5 + `webauthn-rs-core` | Different API; HTTP/JSON contract aligned |
| Client WebAuthn | `@simplewebauthn/browser` | N/A | Consumer brings their own WebAuthn client |
| Body validation | `zod` | `serde` + `parse_request_body` | |
| Auth core | `better-auth`, `@better-auth/core` | `openauth-core` | verification, session, cookies, adapter |
| Serialized state | JSON in verification (challenge string) | CBOR/JSON serialized (`danger-allow-state-serialisation`) | **Design:** Rust needs full ceremony state |
| Persisted credential | Schema fields only (`publicKey` base64) | Schema fields + **hidden `webauthn_credential`** | **Design:** counter/backup/`webauthn-rs` compatibility |

Workspace `webauthn-rs` features used by this crate:

- `danger-allow-state-serialisation` — registration/auth state in verification
- `danger-credential-internals` — persist full `Credential`
- `conditional-ui` — discoverable / empty allow-list

## Swappable backend (OpenAuth only)

| API | Purpose |
| --- | --- |
| `PasskeyWebAuthnBackend` | Trait for injection (fake in tests, `RealPasskeyWebAuthnBackend` in prod) |
| `PasskeyOptions::backend` | Default `Arc<RealPasskeyWebAuthnBackend>` |

Upstream has no equivalent trait; tests mock `@simplewebauthn/server` with Vitest.

## Business logic placement

| Flow | Upstream | OpenAuth |
| --- | --- | --- |
| Generate register options | `routes.ts` → `generateRegistrationOptions` | `routes/registration.rs` → `backend.start_registration` |
| Verify registration | `verifyRegistrationResponse` + `adapter.create` | `backend.finish_registration` + `PasskeyStore::create` |
| Generate auth options | `generateAuthenticationOptions` | `backend.start_authentication` |
| Verify auth | `verifyAuthenticationResponse` + rebuild from `publicKey` | `finish_authentication` + `webauthn_credential` |
| 5 min challenge | `MAX_AGE_IN_SECONDS` in `index.ts` | `CHALLENGE_MAX_AGE_SECONDS` in `challenge.rs` |
| Challenge cookie | `advanced.webAuthnChallengeCookie` | `advanced.webauthn_challenge_cookie` (same default `better-auth-passkey`) |
