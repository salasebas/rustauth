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
- Token storage modes: plain, hashed, encrypted, and custom transforms.
- Schema contributions for SCIM providers, user profiles, and group profiles.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_scim::{scim, ScimOptions, ScimTokenStorage};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(scim(ScimOptions {
        token_storage: ScimTokenStorage::Hashed,
        ..ScimOptions::default()
    }))
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

## Storage Notes

The plugin contributes:

- `scim_providers`
- `scim_user_profiles`
- `scim_group_profiles`

The in-memory adapter works for tests and local runtime usage, but durable SCIM
deployments should use a database adapter. Redis and Valkey crates in this
workspace are rate-limit/secondary-storage integrations, not SCIM identity
stores.

## Status

Experimental beta. The server provisioning surface is implemented and covered,
but API details, schema shape, and parity choices may change before stable
release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
