# openauth-scim

Server-side SCIM 2.0 provisioning plugin for OpenAuth-RS.

## What It Is

`openauth-scim` lets external identity providers provision users and groups
into OpenAuth through SCIM 2.0. It is server-side only and intentionally omits
browser SDKs, dashboard UI, and Better Auth Infrastructure self-service
features.

## What It Provides

- Provider connection management and bearer-token authentication.
- SCIM Users, Groups, Bulk, search, metadata, schema, and resource type routes.
- Filtering, sorting, pagination, projections, weak ETags, and SCIM error
  responses.
- Organization-scoped group provisioning backed by OpenAuth organization teams.
- Token storage modes: hashed (default), plain, encrypted, and custom transforms.
- Schema contributions for SCIM providers, user profiles, and group profiles.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_scim::{scim, ScimOptions, ScimTokenStorage};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(scim(ScimOptions::default()))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run your adapter migration flow after adding the plugin. SCIM clients call
routes under your auth base URL:

```text
https://app.example.com/api/auth/scim/v2
```

Your HTTP integration must allow `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.

## Provider connections (`providerId`)

OpenAuth follows the same storage model as Better Auth: **`providerId` is
globally unique**. One id equals one SCIM connection (one bearer token row), not
“one organization.” Organization scope is optional metadata on that connection:

- Omit `organizationId` to provision users linked to the provider account only.
- Set `organizationId` so list/create/update/delete only touch members of that org.

If you need separate tokens for the same vendor (different orgs, environments, or
apps), assign **different provider ids** (`okta-prod`, `okta-eu`, `entra-hr`).
Regenerating a token for the same `providerId` replaces the stored secret on the
existing row (upsert) instead of deleting the connection first.

We keep global uniqueness rather than a composite `(providerId, organizationId)`
key because upstream does the same: it is a deliberate “one integration id”
design, not a missing composite index. A composite key would be an OpenAuth-only
extension and would complicate management APIs that key off `providerId` alone.

## Provider Tokens

Create or rotate a provider token with an authenticated OpenAuth session:

```text
POST /scim/generate-token
```

Example body:

```json
{
  "providerId": "okta",
  "organizationId": "org_123"
}
```

`organizationId` is optional. When present, the organization plugin must be
installed and the session user must have an allowed organization role.

## Route Summary

Management routes use regular OpenAuth JSON errors:

- `POST /scim/generate-token`
- `GET /scim/list-provider-connections`
- `GET /scim/get-provider-connection?providerId=...`
- `POST /scim/delete-provider-connection`

SCIM protocol routes use RFC 7644-compatible SCIM errors and
`application/scim+json` responses:

- `/scim/v2/Users`
- `/scim/v2/Users/:userId`
- `/scim/v2/Users/.search`
- `/scim/v2/Groups`
- `/scim/v2/Groups/:groupId`
- `/scim/v2/Groups/.search`
- `/scim/v2/.search`
- `/scim/v2/Bulk`
- `/scim/v2/ServiceProviderConfig`
- `/scim/v2/Schemas`
- `/scim/v2/ResourceTypes`

`GET /scim/v2/Me` returns SCIM `501`; provider-scoped tokens are not end-user
aliases.

## Identity validation

User provisioning resolves a canonical email from `userName` and optional
`emails`. Both must produce a valid email address before create, replace, bulk,
or patch mutations persist changes. Empty `userName` values are rejected.

## Filters and metadata

| Surface | Filter handling |
| --- | --- |
| `GET /Users?filter=userName eq "a@b.com"` | Pushed to SQL on `users.email` (Better Auth parity). |
| `GET /Users?filter=...` (anything else) | Parsed with the RFC-style parser, evaluated in memory on each provider-scoped User resource (includes extension profile fields). |
| `POST /Users/.search`, `POST /Groups/.search` | Same parser; Groups always filter in memory. |
| Invalid syntax | `400` with `scimType: invalidFilter`. |

Use `openauth_scim::filters::list_user_filter_uses_database_pushdown` in integrator
code to detect the SQL-backed form.

Better Auth upstream only implements `userName eq` for user list. OpenAuth keeps
that path for compatibility and adds in-memory filtering so enterprise
attributes (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`,
`title`, etc.) and operators like `co` work without a second query language.
Large directories should prefer `userName eq` or pagination (`startIndex` /
`count`, capped by `ServiceProviderConfig.filter.maxResults`).

`ServiceProviderConfig` advertises bulk, sort, weak etag, and extended filter
support that this crate implements server-side.

## Bulk operations

Better Auth **1.6.9** does not implement SCIM Bulk (`bulk.supported: false` in
upstream metadata). OpenAuth implements `POST /scim/v2/Bulk` with two modes:

| Mode | `ScimOptions` | Behavior |
| --- | --- | --- |
| Independent (default) | `bulk_mode: Independent` | RFC-style sequential ops; each mutation runs in its own DB transaction; `failOnErrors` stops the batch. |
| Atomic | `bulk_mode: Atomic` | All mutating ops share one adapter transaction; the first error rolls back earlier ops in the same request (prior successes are reported as `412` in the bulk response). |

`Atomic` requires a database adapter that advertises native transactions
(`AdapterCapabilities::supports_transactions`). The in-memory test adapter does
not qualify; use SQLite/Postgres/MySQL adapters in production.

Bulk operations do not evaluate per-operation `If-Match` headers (unlike direct
`PUT`/`PATCH`/`DELETE` routes).

## Deprovision mode

`ScimDeprovisionMode::DeleteUser` (default) matches Better Auth: `DELETE
/Users/:id` removes the OpenAuth user and linked accounts.

`ScimDeprovisionMode::UnlinkAccount` removes only the current provider account and
SCIM profile (and org membership when the provider is org-scoped). The user row
remains while other provider accounts exist.

## Token storage

`ScimOptions::default()` stores generated SCIM base tokens as SHA-256 hashes.
Use `ScimTokenStorage::Plain` only for local development or when you manage
storage security yourself. Provider token rotation updates the existing
`scim_providers` row instead of deleting and recreating it.

### Migrating from Better Auth plain tokens

If you previously stored SCIM tokens in plain text (Better Auth default or
OpenAuth `ScimTokenStorage::Plain`), switching to hashed default storage
invalidates existing bearer secrets. Regenerate every provider connection via
`POST /scim/generate-token` (or re-seed `default_scim` with new secrets) after
upgrade. There is no in-place migration of raw tokens to hashes.

## Audit hooks

Optional `audit_event: ScimAuditEventResolver` mirrors the SSO plugin pattern:
structured log lines plus an async callback for token generation, user
provision/deprovision, bulk failures, and atomic bulk rollbacks.

## Storage Notes

The plugin contributes:

- `scim_providers`
- `scim_user_profiles`
- `scim_group_profiles`

The in-memory adapter works for tests and local runtime usage, but durable SCIM
deployments should use a database adapter. Redis and Valkey crates in this
workspace are rate-limit/secondary-storage integrations, not SCIM identity
stores.

### MongoDB (future)

OpenAuth does **not** ship a MongoDB `DbAdapter` today. SCIM is tested against
SQLite, PostgreSQL, and MySQL via `openauth-sqlx` / `openauth-tokio-postgres` /
`openauth-deadpool-postgres` (see `tests/scim/db_adapters.rs`). The root
[`docker-compose.yml`](../../docker-compose.yml) includes a `mongodb` service for
local infra experiments only. Upstream Better Auth has
[`@better-auth/mongo-adapter`](https://www.npmjs.com/package/@better-auth/mongo-adapter)
as a separate npm package; a future OpenAuth Mongo adapter would live outside
`openauth-scim` and would need its own SCIM contract tests before this crate
claims support. Telemetry may label connections as `mongodb` when detected, but
that is not storage for SCIM tables.

## Status

Experimental beta. The server provisioning surface is implemented and covered,
but API details, schema shape, and parity choices may change before stable
release.

## Better Auth comparison

Design differences, test parity matrix, and follow-up gaps versus Better Auth
**1.6.9** `packages/scim`:

- [docs/better-auth-design-differences.md](docs/better-auth-design-differences.md)
- [tests/support/scim_parity.md](tests/support/scim_parity.md) (test mapping only)

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
