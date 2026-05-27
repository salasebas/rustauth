# SCIM Test Parity Matrix

This file maps OpenAuth SCIM test modules to the upstream Better Auth SCIM test
areas inspected during implementation.

For intentional design differences, divergences, and prioritized gaps, see
[docs/better-auth-design-differences.md](../docs/better-auth-design-differences.md).

| OpenAuth test module | Upstream reference | Covered behavior |
| --- | --- | --- |
| `tests/scim/routes/users.rs` (+ `isolation.rs`, `provisioning.rs`, `concurrency.rs`) | `packages/scim/src/scim-users.test.ts` + `scim.test.ts` POST Users | SCIM User create, list, filter, get, PUT, PATCH, DELETE, provider isolation (list + item routes), organization isolation, invalid auth, invalid body, duplicate users (PUT + PATCH), link-by-email provisioning, shared-email DELETE semantics, `If-Match: *`, ETag stale rejection, not-found behavior, `externalId` removal fallback, explicit MemoryAdapter cleanup, and Bulk user delete scope hardening. |
| `tests/scim/routes/organization.rs` | `scim.management.test.ts` role-based auth | Org-scoped management, `admin,member` comma-separated roles, GHSA member denial, custom `requiredRole`, creator role. |
| `tests/scim/routes/groups_auth.rs`, `groups_scope.rs` | OpenAuth Groups coverage | Groups bearer auth battery, personal provider rejection, org-shared teams across providers. |
| `tests/scim/routes.rs` | `packages/scim/src/scim.management.test.ts` | Token generation, token replacement, token invalidation, provider list/get/delete, ownership, hooks, token storage modes, and controlled rejection of default or persisted org-scoped SCIM providers when the organization plugin is absent. |
| `tests/scim/routes.rs` | `packages/scim/src/scim.test.ts` | ServiceProviderConfig, Schemas, ResourceTypes, `/Me` unsupported behavior, and SCIM bearer authentication behavior. |
| `tests/scim/patch.rs` | `packages/scim/src/scim-patch.test.ts` | PATCH operation normalization, dotted paths, omitted path payloads, no-op remove, duplicate add, and invalid/no-op update errors. |
| `tests/scim/filters.rs` | `packages/scim/src/scim-filters.ts` | `userName eq "value"` parsing and `invalidFilter` errors. |
| `tests/scim/metadata.rs`, `metadata_snapshot.rs` | `packages/scim/src/scim-metadata.ts` and `packages/scim/src/user-schemas.ts` | SCIM metadata resource shape, schema attributes, resource type URLs, and CI drift snapshots for advertised capabilities. |
| `tests/scim/token.rs` | `packages/scim/src/scim-tokens.ts` and `packages/scim/src/middlewares.ts` | Returned bearer token encoding, padded/unpadded base64url decoding, organization IDs with colons, malformed token rejection, and default-provider token decoding. |
| `tests/scim/store.rs` | `packages/scim/src/routes.ts` storage access | Provider create/find/list/delete conversion and access-policy inputs over `MemoryAdapter`. |
| `tests/scim/routes.rs` | OpenAuth server-only SCIM Group/Bulk coverage | Group create/list/search/get/PUT/PATCH/DELETE, nested group rejection, empty `displayName` rejection, unsupported Group PatchOp path rejection, unknown member rejection in direct PUT/PATCH and Bulk POST/PUT, Bulk group mutation scope hardening, Bulk PatchOp schema validation, per-operation invalid data responses for every User/Group mutation, `failOnErrors`, and `bulkId` member resolution. |
| `tests/scim/db_adapters.rs` | Upstream adapter-backed tests plus OpenAuth adapter contracts | SCIM schema creation, explicit `run_migrations` coverage from core schema to SCIM schema, provider persistence on SQLite, Postgres, and MySQL SQLx adapters plus tokio-postgres and deadpool-postgres, and SQL management access for org-scoped providers without organization tables. |

| `tests/scim/validation.rs` | OpenAuth validation module | Email and SCIM identity validation helpers. |

Additional implementation notes:

- Generated SCIM tokens default to hashed storage; route tests seed plain tokens
  with `scim_options_for_manual_provider_tokens()`.
- Provider token regeneration updates the existing provider row via `upsert`.
- `providerId` is globally unique (same as Better Auth); use distinct ids for
  separate connections — not a composite `(providerId, organizationId)` key.
- User list: only `userName eq` uses SQL pushdown; other filters use in-memory
  evaluation (`list_user_filter_uses_database_pushdown`).
- User provisioning validates resolved email addresses on create, replace, bulk,
  and patch.

- SCIM group routes require organization-scoped providers because groups map to
  OpenAuth organization teams.
- Redis and Valkey are not SCIM storage backends in this repository; they are
  rate-limit stores.
- MongoDB appears in the root Docker Compose stack, but SCIM adapter tests do
  not target it until an OpenAuth MongoDB `DbAdapter` exists.
