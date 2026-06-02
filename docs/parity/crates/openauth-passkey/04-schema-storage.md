# Schema, storage, and serialization

## Logical model

| | Upstream | OpenAuth |
| --- | --- | --- |
| Better Auth model name | `passkey` | Logical contribution `"passkey"` |
| Default physical table | `passkey` (camelCase fields in adapter) | `passkeys` (snake_case columns) |
| Configurable | `options.schema` merge | `PasskeyOptions::passkey_table` |

## Public fields (JSON / API contract)

| Upstream schema field | JSON API | OpenAuth column | Parity |
| --- | --- | --- | --- |
| `name` | `name` | `name` | **Aligned** |
| `publicKey` | `publicKey` | `public_key` | **Aligned** (base64 COSE CBOR on real registration) |
| `userId` | `userId` | `user_id` | **Aligned** (FK → `users.id`, cascade delete) |
| `credentialID` | `credentialID` | `credential_id` | **Aligned** (`#[serde(rename = "credentialID")]`) |
| `counter` | `counter` | `counter` | **Aligned** |
| `deviceType` | `deviceType` | `device_type` | **Aligned** |
| `backedUp` | `backedUp` | `backed_up` | **Aligned** |
| `transports` | `transports` (CSV string) | `transports` | **Aligned** |
| `createdAt` | `createdAt` | `created_at` | **Aligned** |
| `aaguid` | `aaguid` | `aaguid` | **Aligned** |
| — | — | `webauthn_credential` (JSON, **hidden**) | **Design** — not in upstream |

## Indexes and constraints

| Constraint | Upstream schema | OpenAuth |
| --- | --- | --- |
| Index `userId` | Yes | `user_id` indexed |
| Index `credentialID` | Yes | `credential_id` indexed |
| Unique `credentialID` | Not in TS schema (index only) | **UNIQUE** in SQL migrations | **Extension** — duplicates + race → `PREVIOUSLY_REGISTERED` |

Migration tests: SQLite, Postgres, MySQL (`sql.rs`, `sqlite.rs`).

## Challenge state (not in passkey table)

| Field in upstream verification JSON | OpenAuth `ChallengeValue` |
| --- | --- |
| `expectedChallenge` | Embedded in serialized `webauthn-rs` state |
| `userData` { id, name?, displayName? } | `user: PasskeyRegistrationUser` |
| `context` | `context: Option<String>` |
| — | `kind`: `Registration` \| `Authentication` |
| — | `state`: serialized WebAuthn blob | **Design** |

## `PasskeyStore` (OpenAuth)

Operations upstream does inline with `ctx.context.adapter`:

| Method | Use |
| --- | --- |
| `list_by_user` | generate auth options, list endpoint |
| `find_by_id` | update/delete |
| `find_by_credential_id` | verify authentication |
| `create` | verify registration |
| `update_name_for_user` | update passkey |
| `update_after_authentication` | counter + credential state after auth |
| `delete_for_user` | delete passkey |

## Secondary storage (OpenAuth)

Tests confirm challenges and login sessions when `store_session_in_database(false)` (Redis-like). Upstream relies on Better Auth core; no dedicated tests in `packages/passkey` for secondary storage.

| OpenAuth test | What it validates |
| --- | --- |
| `generate_authenticate_options_persists_challenge_in_secondary_storage` | Challenge in secondary store |
| `passkey_login_session_resolves_from_secondary_storage` | Session after verify-auth |

**Label:** **Extension** (OpenAuth core pattern, not passkey-specific upstream).

## Challenge cookies

| Behavior | Upstream | OpenAuth |
| --- | --- | --- |
| Name | `createAuthCookie(webAuthnChallengeCookie)` | `challenge_cookie` + core prefix |
| Configurable prefix | via core cookie prefix | Tests `cookie_config.rs` | **Extension** |
| Cross-subdomain | via core attributes | dedicated test | **Extension** |
