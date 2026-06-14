# HTTP JSON conventions

RustAuth targets [Better Auth](https://www.better-auth.com/) parity for HTTP
request and response bodies. **0.2.0** migrates `rustauth-core` routes to a
single camelCase wire format.

**Parity reference**: `reference/upstream-better-auth/VERSION.md` (currently
`better-auth` 1.6.9).

## Policy

| Surface | Key style | Serde pattern | Example keys |
| --- | --- | --- | --- |
| HTTP request/response bodies | `camelCase` | `#[serde(rename_all = "camelCase")]` on route DTOs | `userId`, `emailVerified`, `callbackURL` |
| Adapter query DSL (`Where`, `Create`, …) | `snake_case` | default Rust field names | `device_code`, `user_id` |
| OAuth / RFC protocol fields | protocol names | unchanged | `device_code`, `expires_in`, `access_token` |
| Plugin options metadata JSON | `camelCase` | documented per plugin | `schema.walletAddress` (SIWE) |
| Database logical column names | `snake_case` | adapter layer only | `email_verified`, `created_at` |
| Signed cookie cache payload | `snake_case` | internal `User`/`Session` serde | not HTTP |

### Allowed exceptions

| Exception | Rationale |
| --- | --- |
| `ApiErrorResponse.originalMessage` | Better Auth client SDK expects this key alongside `code` / `message`. |
| OAuth token and device-authorization endpoints | RFC 6749 / RFC 8628 field names are normative `snake_case`. |
| `StatusBody.status` and other single-word fields | No rename needed. |
| Acronym keys such as `callbackURL`, `errorCallbackURL` | Use `rename = "callbackURL"` with `rename_all = "camelCase"` (`callbackUrl` ≠ `callbackURL`). |

## Implementation (`rustauth-core`)

- **`HttpUser` / `HttpSession`** — typed HTTP views in `crates/rustauth-core/src/api/http_json.rs`.
- **`user_output_value` / `session_output_value`** — all nested `user` and `session`
  JSON in core and plugins (via `SessionUserOutput`) flows through these helpers.
- **Do not** add `rename_all = "camelCase"` on `db/models.rs` `User`/`Session` —
  cookie cache and storage paths require stable snake_case serde.

Fixture JSON for serde tests: `crates/rustauth-core/tests/fixtures/http_json/`.

Inventory test: `crates/rustauth-core/tests/api/http_json_inventory.rs`.

## Protocol surfaces (never camelCase)

| Surface | Examples |
| --- | --- |
| Device authorization | `/device/code`, `/device/token` |
| OAuth provider RFC | `/oauth2/token`, `.well-known/*` |
| SCIM v2 protocol | `/scim/v2/*` |
| Stripe webhook | `/stripe/webhook` |
| WebAuthn option blobs | W3C library serde |

## Related

- Plan 009 — optional `ApiErrorResponse` envelope normalization.
- `crates/rustauth-plugins/README.md` — duration and naming tables.
