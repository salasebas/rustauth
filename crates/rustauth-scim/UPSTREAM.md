# Better Auth 1.6.9 Parity

| Field | Value |
| --- | --- |
| Parity pin | `reference/upstream-better-auth/VERSION.md` (`v1.6.9`, commit `f484269`) |
| Upstream package/path | `@better-auth/scim` at `reference/upstream-src/1.6.9/repository/packages/scim/` |
| Rust crate | `rustauth-scim` |
| Parity level | Server-side high parity plus RustAuth SCIM superset |
| Scope | Server plugin routes, schema, token auth, hooks, metadata, resource mapping, SCIM User provisioning |

RustAuth implements the Better Auth SCIM server plugin where it affects
observable server behavior, then extends it with Groups, Bulk, `.search`,
projection, sorting, pagination, weak ETags, audit hooks, and SCIM profile
tables.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin entrypoint | ✅ | `scim(ScimOptions)` maps to upstream plugin id `scim`. |
| Management routes | ✅ | `POST /scim/generate-token`, list/get/delete provider connections. |
| User CRUD routes | ✅ | `POST/GET/PUT/PATCH/DELETE /scim/v2/Users`; SCIM JSON errors, locations, and org membership provisioning through real organization plugin semantics when installed. |
| Bearer token auth | ✅ | Base64url bearer token with provider and optional organization scope. |
| `scimProvider` schema | ✅ | Global `providerId`, hidden unique token, optional org/user ownership fields. |
| Token storage modes | ✅ | Plain, hashed, encrypted, custom hash, and custom encryption. |
| Hooks | ✅ | Before/after token generation with explicit Rust hook errors. |
| Resource mapping | ✅ | User/account mapping, primary email selection, display name, locations. |
| Metadata routes | 🎯 | Advertises RustAuth's actual capabilities, not only upstream 1.6.9 capabilities. |
| `userName eq` filter | ✅ | Compatibility SQL pushdown for the upstream-supported filter shape. |
| Other filters | 🎯 | Parsed and evaluated in memory for extended User/Group attributes. |
| PATCH Users | ✅ | Supports replace/add/remove, dotted paths, omitted paths, and invalid-op errors. |
| ServiceProviderConfig | 🎯 | Reports RustAuth support for bulk, sort, filter, and weak ETags. |
| Groups | 🎯 | RustAuth extension; maps to organization teams. |
| Bulk | 🎯 | RustAuth extension; independent and atomic modes. |
| `.search` routes | 🎯 | RustAuth extension for Users, Groups, and aggregate resources. |
| Weak ETags | 🎯 | RustAuth extension on direct User/Group item routes. |
| `GET /scim/v2/Me` | ➖ | Returns SCIM `501`; provider-scoped tokens are not end-user aliases. |

## Test Coverage

Verify command: `cargo nextest run -p rustauth-scim`

| Surface | RustAuth tests | Upstream tests | Notes |
| --- | --- | --- | --- |
| Total declarations | 193 `#[test]` / `#[tokio::test]` | 75 direct `it(...)`; 6 `it.for([...])` groups expand to 12 cases (87 total runs) | Counted under `crates/rustauth-scim` and `packages/scim/src/*.test.ts`. |
| Management | `routes/management.rs`, `routes/organization.rs`, `routes.rs` | `scim.management.test.ts` | Token generation, ownership, org roles, list/get/delete, hooks. |
| Users | `routes/users.rs`, `isolation.rs`, `provisioning.rs`, `concurrency.rs` | `scim.test.ts`, `scim-users.test.ts` | Create/list/get/PUT/PATCH/DELETE, scope isolation, conflicts, ETags. |
| PATCH | `patch.rs`, `routes/parity_gaps.rs` | `scim-patch.test.ts` | Operation normalization, path variants, no-op and invalid-op behavior. |
| Auth/token parsing | `token.rs`, `routes/auth.rs` | `scim-tokens.ts`, `middlewares.ts` | Bearer decoding, malformed tokens, default providers, auth failures. |
| Resource mapping | `mappings.rs`, `resources.rs` | `mappings.ts`, `scim-resources.ts`, `utils.ts` | Account ids, primary email, display names, resource URLs. |
| Metadata | `metadata.rs`, `metadata_snapshot.rs`, `routes/metadata.rs` | `scim.test.ts`, `scim-metadata.ts`, `user-schemas.ts` | ServiceProviderConfig, Schemas, ResourceTypes, snapshots. |
| Filters/search | `filters.rs`, `routes/search.rs` | `scim-users.test.ts`, `scim-filters.ts` | Upstream `userName eq` plus RustAuth extended in-memory filters. |
| Groups/Bulk | `routes/groups*.rs`, `routes/bulk*.rs` | None in 1.6.9 | RustAuth extension coverage with no upstream oracle. |
| Storage/adapters | `store.rs`, `schema.rs`, `db_adapters.rs` | Memory and adapter-backed upstream tests | Schema contribution, migrations, SQL adapters, store conversion. |

## Intentional Differences

| Topic | Better Auth | RustAuth | Why |
| --- | --- | --- | --- |
| Default token storage | Plain SCIM token storage | SHA-256 hash by default | Safer production default for bearer secrets. |
| Global provider management | Legacy/global rows can be listed by authenticated sessions | Requires `provider_ownership.enabled = true` without `organizationId` | Avoids silently shared global provider administration. |
| Token rotation | Deletes existing row before `beforeSCIMTokenGenerated` | Upserts after the before hook succeeds | A rejected hook must not invalidate the previous valid token. |
| `userName` identity | Opaque strings allowed in tests | Resolved identity must be a valid email | RustAuth persists users in an email-centered identity model. |
| Created user email state | Does not force verified email | Sets `email_verified: true` for SCIM-created users | External IdP provisioning is treated as authoritative. |
| DELETE user | Deletes the global user row | Defaults to unlinking the SCIM account/profile | Prevents one IdP from destroying shared email-linked identities. |
| Metadata capabilities | Bulk/sort/etag unsupported in 1.6.9 | Advertises implemented RustAuth capabilities | Callers should see the actual server contract. |
| Groups | Not implemented | Organization team-backed Groups | Adds enterprise provisioning while reusing RustAuth org data. |
| Bulk | Not implemented | Independent and atomic bulk modes | Adds RFC-style batch provisioning with adapter-aware transactions. |
| Organization membership provisioning | Direct member insert | Delegates to `rustauth-plugins::organization` when the real plugin is installed | Keeps SCIM org provisioning consistent with member hooks, role validation, and limits. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| SCIM-1 | No open Better Auth 1.6.9 server parity gaps | None | Re-audited against `packages/scim/src/`; open items below are intentional RustAuth extensions or deployment/sibling-crate scope. |

## Intentional Extension / Out-of-Scope Notes

| ID | Topic | Status | Notes |
| --- | --- | --- | --- |
| SCIM-X1 | Groups and Bulk have no Better Auth 1.6.9 oracle | 🎯 Extension | Covered by Rust tests; behavior is RustAuth-defined because upstream 1.6.9 does not implement these routes. |
| SCIM-X2 | Non-email `userName` values are rejected | ➖ Intentional | Secure server identity choice for RustAuth's email-centered user model; opaque IdP usernames remain out of scope for this crate. |
| SCIM-X3 | Bulk per-operation version preconditions | ✅ | Bulk operations honor the SCIM `version` member for Users and Groups, including `PUT`/`PATCH`/`DELETE`; no per-operation HTTP `If-Match` header exists inside a SCIM Bulk request. |
| SCIM-X4 | Atomic Bulk depends on adapter transactions | ➖ Deployment constraint | Use SQL adapters with transaction support for production atomicity; non-transactional adapters fail closed when atomic mode is requested. |
| SCIM-X5 | Rate limiting lives outside this crate | ➖ Sibling/core scope | Route-level throttling belongs to RustAuth/server middleware, not this SCIM plugin crate. |
| SCIM-X6 | MongoDB adapter is not implemented | ➖ Sibling adapter scope | Better Auth's Mongo adapter is outside `rustauth-scim`; Docker Compose MongoDB remains experimental and has no SCIM contract here. |

## Hardening Notes

- Generated SCIM tokens default to hashed storage; use `Plain` only for migration
  or controlled local development.
- Provider ids are globally unique, matching upstream. Use distinct ids for
  separate tenants, environments, or IdP apps.
- Bearer-token authentication fails closed with the same SCIM `401` shape for
  missing, malformed, unknown, or scope-invalid tokens.
- Organization-scoped management requires organization membership and configured
  role checks before token generation, listing, reading, or deletion.
- Durable deployments should use database adapters; the in-memory adapter is for
  tests and local runtime use.

## Upstream Lookup

1. Read `reference/upstream-better-auth/VERSION.md` and confirm Better Auth
   `1.6.9`.
2. If the checkout is missing, run `./scripts/fetch-upstream-better-auth.sh`.
3. Open `reference/upstream-src/1.6.9/repository/packages/scim/`.
4. Compare upstream routes/tests against `crates/rustauth-scim/src/` and
   `crates/rustauth-scim/tests/`.
5. Recount tests with `cargo nextest run -p rustauth-scim -- --list-tests` or
   source declarations, then verify with `cargo nextest run -p rustauth-scim`.

| Upstream source | Rust mapping |
| --- | --- |
| `src/index.ts` | `src/lib.rs`, `src/routes.rs`, `src/options.rs`, `src/schema.rs` |
| `src/routes.ts` | `src/routes/management.rs`, `src/routes/users.rs`, `src/routes/metadata_routes.rs` |
| `src/scim-tokens.ts` | `src/token.rs`, `src/routes/auth_context.rs` |
| `src/middlewares.ts` | `src/routes/auth_context.rs`, `src/errors.rs` |
| `src/mappings.ts`, `src/scim-resources.ts`, `src/utils.ts` | `src/mappings.rs`, `src/resources.rs` |
| `src/scim-filters.ts` | `src/filters.rs` |
| `src/patch-operations.ts` | `src/patch.rs` |
| `src/scim-metadata.ts`, `src/user-schemas.ts` | `src/metadata.rs`, `src/resources.rs` |
| `src/scim*.test.ts` | `tests/scim/**`, `tests/support/scim_parity.md` |

## Links

- [README](./README.md)
- [Upstream parity index](../../docs/parity/README.md)
