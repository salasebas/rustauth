# Plugin configuration

## Main `PasskeyOptions` table

| Upstream option (`PasskeyOptions`) | OpenAuth (`PasskeyOptions`) | Upstream default | OpenAuth default | Parity |
| --- | --- | --- | --- | --- |
| `rpID` | `rp_id` | hostname from `baseURL` or `"localhost"` | Same via `webauthn_config` | **Aligned** |
| `rpName` | `rp_name` | `appName` on register | `context.app_name` | **Aligned** |
| `origin` | `origin` (`Vec<String>`) | `null` (client/header) | `[]` (equiv. header/base_url) | **Aligned** (type differs: upstream `string \| string[] \| null`) |
| `authenticatorSelection` | `authenticator_selection` | Merge with `residentKey: preferred`, `userVerification: preferred` | Same defaults in `AuthenticatorSelection` | **Aligned** |
| `advanced.webAuthnChallengeCookie` | `advanced.webauthn_challenge_cookie` | `"better-auth-passkey"` | Same | **Aligned** |
| `schema` (`mergeSchema` — rename fields, types) | `passkey_table` only (physical table name) | merge camelCase fields | default `passkeys` | **Gap:** no field merge; see [08-implementation-audit.md §6](./08-implementation-audit.md) |
| — | `backend: Arc<dyn PasskeyWebAuthnBackend>` | — | `RealPasskeyWebAuthnBackend` | **Extension** testability |
| — | `passkey_table` | table `passkey` | `"passkeys"` | **Design** Rust plural/snake convention |

### Origins and loopback (OpenAuth only)

OpenAuth implements explicit rules in `webauthn.rs` (unit tests):

| Rule | Reason |
| --- | --- |
| Loopback origins (`localhost`, `127.0.0.1`, `::1`) allow any port | Local DX |
| Production origins require exact port | Security |
| Mixing loopback + production disables global “any port” | Avoid bypass |

Upstream delegates more to SimpleWebAuthn / single `expectedOrigin` per request.

## `registration` / `PasskeyRegistrationOptions`

| Upstream field | OpenAuth | Default | Parity |
| --- | --- | --- | --- |
| `requireSession` | `require_session` | `true` | **Aligned** |
| `resolveUser` | `resolve_user` / `resolve_user_async` | — | **Aligned** |
| `afterVerification` | `after_verification` / `after_verification_async` | — | **Aligned** |
| `extensions` | `extensions` / `extensions_resolver` | — | **Aligned** |

### Callback types

| Upstream | OpenAuth | Difference |
| --- | --- | --- |
| Receives `ctx: GenericEndpointContext` | `ResolveRegistrationUserInput`, `PasskeyExtensionsInput`, etc. | **Design** idiomatic Rust without generic `ctx` |
| `afterVerification` gets `verification`, `user`, `clientData`, `context` | `AfterRegistrationVerificationInput` (subset) | **Aligned** on fields used for `userId` override |
| Invalid `userId` (e.g. number) | Rejection via Rust types + override tests | Upstream tests `userId: 123` → error | **Aligned** (different mechanism) |

## `authentication` / `PasskeyAuthenticationOptions`

| Field | Parity |
| --- | --- |
| `extensions` | **Aligned** |
| `afterVerification` | **Aligned** (OpenAuth does not expose SimpleWebAuthn `verification` object; passes `credential_id` + `client_data`) |

## Time constants

| Constant | Value | Upstream location | OpenAuth location |
| --- | --- | --- | --- |
| Challenge max age | 300 s | `index.ts` `MAX_AGE_IN_SECONDS` | `challenge.rs` `CHALLENGE_MAX_AGE_SECONDS` |

## Fresh session (registration)

| Aspect | Upstream | OpenAuth |
| --- | --- | --- |
| Middleware | `freshSessionMiddleware` from `better-auth/api` | `session_is_fresh` + core `fresh_age` |
| Tests | Implicit in session flows | `generate_register_options_rejects_stale_session`, `verify_registration_rejects_stale_session`, `accepts_fresh_session` | **Extension** explicit coverage |

## Authenticator selection (query + options)

| `authenticatorAttachment` query | OpenAuth mapping |
| --- | --- |
| `platform` | `AuthenticatorAttachment::Platform` |
| `cross-platform` | `CrossPlatform` |
| invalid | `400` `BAD_REQUEST` |

Defaults on registration (both): `resident_key: preferred`, `user_verification: preferred` before user option merge.
