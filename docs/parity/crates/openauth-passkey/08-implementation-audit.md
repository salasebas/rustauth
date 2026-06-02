# Implementation audit (source code)

Line-by-line review of `packages/passkey/src/*` (upstream v1.6.9) against `crates/openauth-passkey/src/*` and tests. **READMEs were not used as primary sources.**

File references:

| Upstream | OpenAuth |
| --- | --- |
| `routes.ts` | `routes/registration.rs`, `routes/authentication.rs`, `routes/management.rs` |
| `index.ts` | `lib.rs` |
| `schema.ts` | `schema.rs` |
| `types.ts` | `options.rs` |
| `client.ts` | *(not ported)* |
| `passkey.test.ts` | `tests/passkey/*.rs` |

---

## 1. Registration — `generate-register-options`

| Behavior | Upstream (`routes.ts` ~250–327) | OpenAuth (`registration.rs` + `webauthn.rs`) | Status |
| --- | --- | --- | --- |
| Fresh session middleware if `requireSession: true` | `freshSessionMiddleware` on GET | `session_is_fresh` when session + `require_session` | Aligned |
| No middleware if `requireSession: false` | `use: []` | No session required | Aligned |
| Resolve user | `resolveRegistrationUser` | `registration_user` | Aligned |
| Pre-auth with optional session | `getSessionFromCtx` in resolve | `registration_user` prefers session | Aligned |
| Pre-auth **without** fresh check | No fresh middleware | Same | Aligned |
| Query `context` → resolveUser | `ctx.query?.context` | `query_param("context")` | Aligned |
| Query `name` → WebAuthn `userName` | `ctx.query?.name \|\| user.name` | Query `name` overrides; copies to `display_name` when missing | **Nuance** (displayName) |
| Query `authenticatorAttachment` | Merge into `authenticatorSelection` | `AuthenticatorAttachment::from_query` or 400 | Aligned |
| `excludeCredentials` | All user passkeys by `credentialID` | Full credential JSON or legacy `credential_id` string | **Aligned** (legacy closed) |
| WebAuthn `user.id` (ceremony handle) | `generateRandomString(32)` | `Uuid::new_v4().as_bytes()` | **Design** (both opaque) |
| `user.id` in verification JSON | **Account id** | `ChallengeValue.user.id` = account | Aligned |
| `rpName` | `opts.rpName \|\| appName` | Same | Aligned |
| `rpID` | `getRpID(opts, baseURL)` | `webauthn_config` | Aligned |
| `attestationType` | `"none"` | `AttestationConveyancePreference::None` | Aligned |
| Default `residentKey` / `userVerification` | `preferred` in merge | `AuthenticatorSelection::default()` + JSON | Aligned in published JSON |
| Internal `require_resident_key` | SimpleWebAuthn merge | `require_resident_key(false)` then JSON override | **Nuance** (§ WebAuthn builder) |
| Registration extensions | `resolveExtensions(..., ctx)` | `resolve_extensions` + `PasskeyExtensionsInput { context }` | Aligned |
| Cookie + verification TTL | 300 s, 32-char token | `CHALLENGE_MAX_AGE_SECONDS`, `generate_random_string(32)` | Aligned |
| Stored challenge | `expectedChallenge` + `userData` + `context` JSON | `ChallengeValue` + serialized `webauthn-rs` state | **Design** |

### `displayName` (pre-auth)

Upstream e2e expects `resolveUser` to set `displayName` in options JSON. OpenAuth: `start_registration` uses `display_name` when provided; test `generate_register_options_uses_resolve_user_display_name` covers this.

---

## 2. Registration — `verify-registration`

| Behavior | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| Body `response` + optional `name` | zod | `VerifyRegistrationBody` | Aligned |
| Origin | `options.origin \|\| header` | `verification_webauthn_config` | Aligned |
| Cookie / verification | Same pattern | `challenge_token` + `find_challenge` | Aligned |
| Challenge kind | Implicit | Rejects `kind != Registration` | **Extension** |
| Session if `requireSession` | `freshSessionMiddleware` | Session + fresh | Aligned |
| `userData.id` vs session | Rejects mismatch | `not_allowed()` | Aligned |
| Crypto verify | `verifyRegistrationResponse`, `requireUserVerification: false` | `finish_registration` + UV policy (OPE-48) | **Design** |
| `afterVerification` → `userId` | Validates non-empty string | `RESOLVED_USER_INVALID` if empty | Aligned |
| `afterVerification` non-string userId | Upstream test rejects | Rust `String` return type | **N/A** |
| Stored passkey name | `ctx.body.name` | `body.name` in `store.create` | Aligned |
| `publicKey` | base64 COSE | `credential_output` | Aligned |
| Duplicate `credentialID` | Implicit on create | Pre-check + UNIQUE + race | **Extension** |
| Delete verification on success | Yes | `delete_verification` | Aligned |
| Catch verify failure | `INTERNAL_SERVER_ERROR` + `FAILED_TO_VERIFY_REGISTRATION` | **500** + same code | **Aligned** |

---

## 3. Authentication — `generate-authenticate-options`

| Behavior | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| With session | `allowCredentials` by `credentialID` + transports | Credentials from store + legacy ids | **Aligned** |
| Without session | No `allowCredentials` | Empty → discoverable | Aligned |
| `userVerification` | `"preferred"` | `UserVerificationPolicy::Preferred` | Aligned |
| Auth extensions | `resolveExtensions(..., ctx)` | `PasskeyExtensionsInput { context, user_id }` | **Partial** vs full `ctx` |
| Verification `userData.id` | `session?.user.id \|\| ""` | Optional `ChallengeValue.user` | Aligned |

### Discoverable (OpenAuth)

Empty allow-list uses `StoredAuthenticationState::Discoverable` and `uvm: Some(true)` — **not in upstream passkey package**; OpenAuth extension.

---

## 4. Authentication — `verify-authentication`

| Behavior | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| Empty origin | `BAD_REQUEST` `"origin missing"` | Same | Aligned |
| Passkey lookup | By `resp.id` | `find_by_credential_id` | Aligned |
| Missing passkey | `PASSKEY_NOT_FOUND` | Same | Aligned |
| Session challenge vs passkey user | **No** | Rejects mismatch → `PASSKEY_NOT_FOUND` | **Design** (stricter) |
| Credential for verify | Rebuild from `publicKey` | `webauthn_credential` JSON | **Design** (legacy `publicKey`-only verify not ported) |
| `afterVerification` | `verification`, `clientData`, `ctx` | `credential_id` + `client_data` | **Design** (narrower API) |
| Update counter | Yes | `update_after_authentication` | Aligned |
| Session + cookie | `createSession` + `setSessionCookie` | `create_session_for_user` + cookies | Aligned |
| Deleted user | `INTERNAL_SERVER_ERROR` "User not found" | **500** "User not found" | **Aligned** |
| Session IP | Better Auth core | `resolve_client_ip` (anti-spoof test) | **Extension** |

---

## 5. Management

| Endpoint | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| List | `sessionMiddleware`, JSON array | Session required; no `webauthn_credential` in JSON | Aligned |
| Delete `{ id }` | `requireResourceOwnership` | Manual ownership; 404 `PASSKEY_NOT_FOUND` | Aligned |
| Delete other user | `UNAUTHORIZED` | `unauthorized()` | Aligned |
| Update other user | `YOU_ARE_NOT_ALLOWED...` | `not_allowed()` | Aligned |
| List response cookies | JSON only | JSON only (no `Set-Cookie`) | **Aligned** |

---

## 6. Configuration not fully ported

| Upstream `PasskeyOptions` | OpenAuth | Notes |
| --- | --- | --- |
| `schema` (`mergeSchema`) | `passkey_table` only | **Gap:** no per-field rename |
| `origin: string \| string[] \| null` | `Vec<String>` | OpenAuth supports multiple configured origins |

---

## 7. WebAuthn extensions

| Flow | Upstream | OpenAuth |
| --- | --- | --- |
| Registration | `({ ctx }) => ...` | `PasskeyExtensionsInput { context }` |
| Authentication | `({ ctx }) => ...` | `PasskeyExtensionsInput { context, user_id }` |

**Gap:** no full HTTP `ctx` in resolvers; integrators use static config or closures.

---

## 8. WebAuthn builder (`RealPasskeyWebAuthnBackend`)

| Detail | OpenAuth | Upstream |
| --- | --- | --- |
| `require_resident_key` in builder | `false` then JSON override | `residentKey: "preferred"` in selection |
| Loopback ports | `origins_allow_any_port` | Not explicit in passkey package |

---

## 9. Tests outside `packages/passkey`

| Location | Coverage | Replicated in OpenAuth? |
| --- | --- | --- |
| `passkey.test.ts` | 19 server cases | Yes (+ more) |
| `client.test.ts` | Client extensions | N/A |
| `e2e/smoke/passkey-preauth.spec.ts` | Pre-auth + displayName | Yes (integration test) |
| `openauth/tests/public_api.rs` | Feature re-export | Yes |

---

## 10. HTTP error summary

| Scenario | Upstream | OpenAuth |
| --- | --- | --- |
| Register verify catch | 500 `FAILED_TO_VERIFY_REGISTRATION` | **500** |
| Auth verify missing user | 500 "User not found" | **500** |
| Stale session | 403 `SESSION_NOT_FRESH` | **403** |

Aligned as of June 2026.

---

## 11. Fresh session HTTP

See [09-ecosystem-and-edge-cases.md §3](./09-ecosystem-and-edge-cases.md).

## 12. Origin: generate vs verify

See [09-ecosystem-and-edge-cases.md §2](./09-ecosystem-and-edge-cases.md).

## 13. Checklist

- [x] 7 server routes
- [x] Cookie `better-auth-passkey` + verification
- [x] Plugin id `passkey`
- [x] 14 `PASSKEY_ERROR_CODES`
- [x] GHSA cross-user update/delete
- [x] Pre-auth `resolveUser` + `context`
- [x] `afterVerification` registration and auth
- [x] Discoverable without session
- [x] `credentialID` in JSON
- [x] Hidden `webauthn_credential`
- [x] UNIQUE `credential_id`
- [ ] `mergeSchema` — optional product requirement
- [x] Auth extensions `user_id` (partial vs full `ctx`)
- [x] Pre-auth `displayName` test
- [x] `SESSION_NOT_FRESH` **403**
- [x] Legacy exclude/allow credential ids
- [ ] Verify-auth from `publicKey` only (legacy rows) — not ported
