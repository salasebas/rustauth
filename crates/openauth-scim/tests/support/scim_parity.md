# SCIM Test Parity Matrix

This file maps OpenAuth SCIM test modules to the upstream Better Auth SCIM test
areas inspected during implementation.

| OpenAuth test module | Upstream reference | Covered behavior |
| --- | --- | --- |
| `tests/scim/routes.rs` | `packages/scim/src/scim-users.test.ts` | SCIM User create, list, filter, get, PUT, PATCH, DELETE, provider isolation, organization isolation, invalid auth, invalid body, duplicate users, and not-found behavior. |
| `tests/scim/routes.rs` | `packages/scim/src/scim.management.test.ts` | Token generation, token replacement, token invalidation, provider list/get/delete, ownership, organization role checks, GHSA regular-member denial, hooks, and token storage modes. |
| `tests/scim/routes.rs` | `packages/scim/src/scim.test.ts` | ServiceProviderConfig, Schemas, ResourceTypes, and SCIM bearer authentication behavior. |
| `tests/scim/patch.rs` | `packages/scim/src/scim-patch.test.ts` | PATCH operation normalization, dotted paths, omitted path payloads, no-op remove, duplicate add, and invalid/no-op update errors. |
| `tests/scim/filters.rs` | `packages/scim/src/scim-filters.ts` | `userName eq "value"` parsing and `invalidFilter` errors. |
| `tests/scim/metadata.rs` | `packages/scim/src/scim-metadata.ts` and `packages/scim/src/user-schemas.ts` | SCIM metadata resource shape, schema attributes, and resource type URLs. |
| `tests/scim/token.rs` | `packages/scim/src/scim-tokens.ts` and `packages/scim/src/middlewares.ts` | Returned bearer token encoding, padded/unpadded base64url decoding, organization IDs with colons, malformed token rejection, and default-provider token decoding. |
| `tests/scim/store.rs` | `packages/scim/src/routes.ts` storage access | Provider create/find/list/delete conversion and access-policy inputs over `MemoryAdapter`. |
| `tests/scim/db_adapters.rs` | Upstream adapter-backed tests plus OpenAuth adapter contracts | SCIM schema creation and provider persistence on SQLite, Postgres, and MySQL SQLx adapters. |
