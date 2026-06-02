# Error codes

Upstream source: `packages/passkey/src/error-codes.ts`  
OpenAuth source: `crates/openauth-passkey/src/errors.rs` + `response.rs` + handlers.

## Plugin registration

All **14** codes from `PASSKEY_ERROR_CODES` are registered on both sides with the same identifiers and equivalent messages (minor wording on `RESOLVE_USER_REQUIRED`).

| Code | Used in OpenAuth routes? | Used upstream server? | Notes |
| --- | --- | --- | --- |
| `CHALLENGE_NOT_FOUND` | Yes | Yes | Missing cookie/verification or wrong challenge type |
| `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` | Yes | Yes | Registration user mismatch; **update** on others’ passkey |
| `FAILED_TO_VERIFY_REGISTRATION` | Yes | Yes | Crypto / origin failure |
| `PASSKEY_NOT_FOUND` | Yes | Yes | Unknown credential or passkey id |
| `AUTHENTICATION_FAILED` | Yes | Yes | Failed auth verify |
| `UNABLE_TO_CREATE_SESSION` | Registered | Yes | OpenAuth: core session error path |
| `FAILED_TO_UPDATE_PASSKEY` | Registered | Yes | |
| `PREVIOUSLY_REGISTERED` | Yes | Implicit in flows | Duplicate `credential_id` |
| `REGISTRATION_CANCELLED` | Registered | **Client** (`WebAuthnError`) | **N/A server** OpenAuth |
| `AUTH_CANCELLED` | Registered | **Client** | **N/A server** |
| `UNKNOWN_ERROR` | Registered | **Client** | **N/A server** |
| `SESSION_REQUIRED` | Yes | Yes | Default `require_session` |
| `RESOLVE_USER_REQUIRED` | Yes | Yes | Pre-auth without `resolve_user` |
| `RESOLVED_USER_INVALID` | Yes | Yes | Empty id/name |

## Additional runtime codes (OpenAuth)

| Code | Source | Upstream equivalent |
| --- | --- | --- |
| `UNAUTHORIZED` | `response.rs` | `UNAUTHORIZED` (session, delete on others’ passkey) |
| `SESSION_NOT_FRESH` | `registration.rs` | `freshSessionMiddleware` rejection |
| `BAD_REQUEST` | invalid attachment | Zod / APIError |
| `origin missing` | auth verify without origin | `BAD_REQUEST` message `"origin missing"` |

## Client → code mapping (upstream only)

`client.ts` maps browser `WebAuthnError` to `PREVIOUSLY_REGISTERED`, `REGISTRATION_CANCELLED`, `AUTH_CANCELLED`. **Does not apply** to OpenAuth server-only; the integrator’s client must map errors if needed.

## HTTP semantics for ownership errors (GHSA-4vcf-q4xf-f48m)

| Operation | Other user’s resource | Upstream | OpenAuth |
| --- | --- | --- | --- |
| Delete | Another user’s passkey | `UNAUTHORIZED` | `UNAUTHORIZED` | **Aligned** |
| Update | Another user’s passkey | `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` | Same code | **Aligned** |
| Delete/update | Non-existent id | throw APIError | `404` `PASSKEY_NOT_FOUND` | **Aligned** observable |

## HTTP status (verify edges / fresh session)

Reviewed in `routes.ts` vs `routes/*.rs` ([08-implementation-audit.md §10](./08-implementation-audit.md)):

| Scenario | Upstream HTTP | OpenAuth HTTP |
| --- | --- | --- |
| `verify-registration` catch (verify failure) | 500 | **500** |
| `verify-authentication` missing DB user | 500 | **500** |
| `verify-registration` without `Origin`/origin | 400 | 400 |
| `verify-authentication` without origin | 400 (`origin missing`) | 400 |
| Stale session (registration) | **403** `SESSION_NOT_FRESH` | **403** `SESSION_NOT_FRESH` |

## Error JSON shape

OpenAuth test: `passkey_error_responses_use_core_camel_case_shape` — aligned with OpenAuth core error shape (camelCase), comparable to Better Auth API responses.
