# Test coverage

OpenAuth count command:

```bash
cargo test -p openauth-passkey -- --list
```

**Total: ~60** integration tests + unit tests in `webauthn.rs` + 1 doc-test in `lib.rs` (exact count varies with ignored SQL tests).

Upstream (`packages/passkey`, Vitest):

| File | `describe` | `it` | Scope |
| --- | ---: | ---: | --- |
| `passkey.test.ts` | 2 | **19** (17 functional + 2 TTL) | Server |
| `client.test.ts` | 1 | 2 | Browser client |
| **Package total** | **3** | **21** | |

### Upstream tests outside `packages/passkey`

| Location | Cases | Covered in OpenAuth |
| --- | --- | --- |
| `e2e/smoke/test/passkey-preauth.spec.ts` | 1 (HTTP pre-auth, `context`, `displayName`) | `resolve_user`/`context` + `generate_register_options_uses_resolve_user_display_name` |
| `crates/openauth/tests/public_api.rs` | `passkey_feature_reexports_passkey_crate` | Yes |

## Comparative summary

| Metric | Upstream (server) | OpenAuth |
| --- | ---: | ---: |
| Package test cases | 19 server + 2 client | ~59 integration + 6 unit + 1 doc |
| WebAuthn mock | `@simplewebauthn/server` verify* mocks | `PasskeyWebAuthnBackend` fake + **real** `webauthn-rs` tests |
| SQL migrations | Not in passkey package | SQLite + Postgres + MySQL |
| OpenAPI | No | Yes |
| Secondary storage | No | Yes |
| Cookie prefix / domain | Partial (1 test asserts cookie) | 3 dedicated tests |
| TS client | 2 tests | N/A |

## Upstream inventory (`passkey.test.ts`)

| Test | Behavior covered |
| --- | --- |
| should generate register options | Options + `better-auth-passkey` cookie |
| should generate register options without session when resolveUser is provided | Pre-auth + resolveUser |
| should require resolveUser when session is not available | `RESOLVE_USER_REQUIRED` |
| should call afterVerification and allow userId override | Link pre-auth → real user |
| should reject invalid userId returned from afterVerification | Invalid userId type |
| should reject afterVerification override that mismatches session user | Override ≠ session user |
| should generate authenticate options | With session + allowCredentials |
| should generate authenticate options without session | Discoverable |
| should list user passkeys | List shape |
| should update a passkey | Rename |
| should not delete a passkey that doesn't exist | Delete error |
| should delete a passkey | Happy path delete |
| should not allow deleting another user's passkey | GHSA delete |
| should not allow updating another user's passkey | GHSA update |
| should verify passkey authentication and return user | Mock verify + session |
| should compute expirationTime per-request, not at init time | Registration TTL |
| should compute expirationTime per-request for authentication options | Auth TTL |

### `client.test.ts` (out of OpenAuth scope)

| Test | Behavior |
| --- | --- |
| merges registration extensions and returns WebAuthn response | Client `addPasskey` |
| merges authentication extensions and returns WebAuthn response | Client `signIn.passkey` |

## OpenAuth inventory by file

### `tests/passkey/register.rs`

Covers upstream register flows plus extensions: stale session **403**, duplicate credential, real WebAuthn backend, `after_registration_verification` override rules, legacy `excludeCredentials`, `generate_register_options_uses_resolve_user_display_name`, etc.

### `tests/passkey/authenticate.rs`

Covers discoverable/session auth, TTL per request, session-scoped credential rejection, deleted user **500**, legacy `allowCredentials`, async `after_verification`, IP resolver anti-spoof, etc.

### `tests/passkey/management.rs`

GHSA ownership, `credentialID` serialization, `404 PASSKEY_NOT_FOUND`.

### Other integration files

| File | Theme |
| --- | --- |
| `schema.rs` | Schema contribution |
| `openapi.rs` | OpenAPI metadata |
| `sqlite.rs` / `sql.rs` | Migrations + unique index |
| `cookie_config.rs` | Prefix, domain, cookie read |
| `secondary_storage.rs` | Redis-like storage |

### Unit tests `src/webauthn.rs`

Origins, AAGUID, COSE `publicKey` contract.

## Matrix: upstream behavior vs OpenAuth test

| Upstream behavior (17 server tests) | Covered in OpenAuth |
| --- | --- |
| Generate register options | Yes (+ more variants) |
| Pre-auth resolveUser | Yes |
| resolveUser required | Yes |
| afterVerification userId override | Yes |
| Reject invalid afterVerification userId | Partial (Rust types; not identical numeric test) |
| Reject session mismatch on afterVerification | Yes |
| Generate auth options (session / no session) | Yes |
| List / update / delete passkeys | Yes |
| Cross-user delete/update | Yes |
| Verify authentication + session | Yes |
| Per-request challenge expiration | Yes |
| Client extension merge | **N/A** (client-only) |

## Server test gaps

| Gap | Severity | Note |
| --- | --- | --- |
| Exact `userId: 123` in afterVerification | Low | Rust prevents at compile time |
| Real browser E2E | N/A | Integrator responsibility |
| Line-by-line OpenAPI description parity | Low | **Design** — do not copy TS text |
