# Better Auth ecosystem and edge cases

Findings from a **third pass** reading `routes.ts`, `webauthn.rs`, `routes.rs`, tests (`support.rs`, `register.rs`), core plugins (`last-login-method`, `anonymous`), and e2e smoke — not only `packages/passkey`.

---

## 1. Integrations outside `openauth-passkey`

The passkey plugin is **not isolated**. Other plugins observe its routes:

| Plugin | Upstream (Better Auth 1.6.9) | OpenAuth | Observed route |
| --- | --- | --- | --- |
| `last-login-method` | `path.includes("/passkey/verify-authentication")` → `"passkey"` | `openauth-plugins` `last_login_method/resolve.rs` | Same |
| `anonymous` | `after` hook if path `startsWith("/passkey/verify-authentication")` | `openauth-plugins` `anonymous/hooks.rs` | Same |

**Implication:** successful passkey login must still emit a session cookie on `verify-authentication` for anonymous linking and last-login-method. OpenAuth does this via `session_response_cookies` (session + secondary storage tests).

This is deployment parity when using those plugins, not passkey-crate parity alone.

---

## 2. Origin: generate vs verify (internal OpenAuth asymmetry)

Two helpers in `routes.rs`:

| Function | Used in | If `PasskeyOptions::origin` empty |
| --- | --- | --- |
| `webauthn_config` | `generate-*-options` | `Origin` header → **`base_url`** → `http://localhost` |
| `verification_webauthn_config` | `verify-*` | **`Origin` header only**; missing → verify fails |

Upstream verify uses `options?.origin || header || ""` — **does not** use `baseURL` as `expectedOrigin`. Aligned with upstream verify.

**Edge case:** options can be generated without `Origin` (OpenAuth uses `base_url`), but verify without `Origin` or configured `origin` **fails** (`verify_*_rejects_missing_origin_when_origin_is_not_configured`). Browsers normally send `Origin` on POST; server-to-server integrations must set `PasskeyOptions::origin` or the header.

**Error code nuance on missing origin:**

| Endpoint | OpenAuth | Upstream |
| --- | --- | --- |
| `verify-registration` | `FAILED_TO_VERIFY_REGISTRATION` | Same |
| `verify-authentication` | `"origin missing"` (code = message) | `BAD_REQUEST` `"origin missing"` |

---

## 3. Fresh session

| Situation | Upstream `freshSessionMiddleware` | OpenAuth `registration.rs` |
| --- | --- | --- |
| No session (require session) | 401 `UNAUTHORIZED` | 401 `SESSION_REQUIRED` |
| Stale session | **403** + `SESSION_NOT_FRESH` | **403** + `SESSION_NOT_FRESH` (`session_not_fresh()`) |

Tests assert **403** + `SESSION_NOT_FRESH` (`generate_register_options_rejects_stale_session`, `verify_registration_rejects_stale_session`).

`fresh_age == 0` disables the check in both worlds.

---

## 4. `list-user-passkeys` without session cookies in response

OpenAuth `management.rs` returns only the JSON array (no `Set-Cookie`), aligned with upstream `ctx.json(passkeys)`.

---

## 5. OpenAPI / public schema

| Field | Upstream list OpenAPI | OpenAuth `passkey_openapi_schema()` |
| --- | --- | --- |
| `updatedAt` | In list doc **required** | **Not** in model |
| `createdAt` | In plugin schema | Yes, nullable |
| `webauthn_credential` | N/A | Hidden in API JSON (`#[serde(skip)]`) |

Upstream list docs may require `updatedAt` that the TS plugin schema **does not define** — upstream inconsistency, not OpenAuth.

---

## 6. `FakeWebAuthnBackend` vs `RealPasskeyWebAuthnBackend` (tests)

| Aspect | Fake (most integration) | Real (unit + some tests) |
| --- | --- | --- |
| WebAuthn `user.id` in options JSON | **Account id** | **Random UUID** bytes |
| Crypto | No real verify | Full `webauthn-rs` |
| `finish_authentication` credential update | `credential: None` | Updates counter + credential JSON |

Happy-path register tests often use **Fake**; random ceremony handle is covered by `real_webauthn_backend_uses_random_registration_user_handle`.

---

## 7. webauthn-rs details not visible in upstream TS

| Behavior | OpenAuth `webauthn.rs` | Upstream SimpleWebAuthn |
| --- | --- | --- |
| `reject_synchronised_authenticators(false)` | Explicit on registration | Library default |
| `allow_backup_eligible_upgrade` | Configured per ceremony | Implicit |
| `uvm` on discoverable auth | `uvm: Some(true)` | Not in passkey package |
| `rp_id` ⊆ origin domain | Validated in `core()` | Delegated |

---

## 8. `require_resident_key(false)` in builder

Registration builder calls `.require_resident_key(false)` then **overwrites** `authenticatorSelection` in published JSON (`residentKey: preferred` by default). Tests assert JSON; internal ceremony state follows builder + UV policy (OPE-48).

---

## 9. Callbacks vs upstream

| Callback | Upstream receives | OpenAuth receives |
| --- | --- | --- |
| `registration.afterVerification` | SimpleWebAuthn `verification`, `ctx`, `user`, `clientData`, `context` | Subset → optional `userId` only |
| `authentication.afterVerification` | `verification`, `clientData`, `ctx` | `credential_id`, `client_data` |

**Design:** narrower Rust API; no library `verification` object exposed.

---

## 10. Upstream e2e vs Rust tests

| Test | Validates | OpenAuth |
| --- | --- | --- |
| `e2e/smoke/passkey-preauth.spec.ts` | Pre-auth HTTP; `displayName` from resolver | `generate_register_options_uses_resolve_user_display_name` + context tests |

---

## 11. Extra OpenAuth error codes (not in upstream `PASSKEY_ERROR_CODES`)

| Code | Registered on plugin | Use |
| --- | --- | --- |
| `SESSION_NOT_FRESH` | Core / route | Register generate/verify |
| `BAD_REQUEST` | No | Invalid `authenticatorAttachment` |
| `UNAUTHORIZED` | No | Missing session in management |

---

## 12. Third-pass findings summary

| # | Finding | Severity |
| --- | --- | --- |
| 1 | `anonymous` + `last-login-method` on `/passkey/verify-authentication` | Info |
| 2 | `webauthn_config` vs `verification_webauthn_config` (`base_url` only on generate) | Info |
| 3 | ~~`SESSION_NOT_FRESH` 401 vs 403~~ | **Closed** (403) |
| 4 | ~~List passkeys returned session cookies~~ | **Closed** |
| 5 | Fake backend uses account id in options JSON | Test-only nuance |
| 6 | ~~No `displayName` pre-auth test~~ | **Closed** |
| 7 | Auth extensions: `user_id` added; full `ctx` still partial | Medium |
