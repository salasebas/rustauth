# Better Auth SCIM — design differences (OpenAuth)

Reference upstream: Better Auth `@better-auth/scim` **v1.6.9**  
`reference/upstream-src/1.6.9/repository/packages/scim/`

OpenAuth crate: `crates/openauth-scim`

Related: [docs/parity/openauth-scim/README.md](../../../docs/parity/openauth-scim/README.md) (canonical), [README](../README.md), [tests/support/scim_parity.md](../tests/support/scim_parity.md), [parity plan](../../../docs/superpowers/plans/2026-05-12-scim-upstream-parity.md)

---

## 1. Executive summary

OpenAuth treats Better Auth **1.6.9** `packages/scim` as a **behavioral reference** for server-side user provisioning, provider-token management, and SCIM metadata—not as a structure to copy line by line.

| Dimension | Better Auth 1.6.9 | OpenAuth `openauth-scim` |
| --- | --- | --- |
| Scope | Users, 4 management routes, User metadata | Users, Groups, Bulk, `.search`, `/Me` (501), enterprise schema |
| Default token storage | `plain` (`src/index.ts`) | `Hashed` (`src/options.rs`) |
| Token rotation | Delete row, then `create` (`src/routes.ts`) | `upsert` on same `provider_id` (`management.rs`) |
| List filters | `userName eq` only → DB (`src/scim-filters.ts`) | Same SQL pushdown + in-memory RFC parser (`filters.rs`) |
| ServiceProviderConfig | `bulk` / `sort` / `etag`: false | true where implemented (`metadata.rs`) |
| TypeScript client | `src/client.ts` | Not ported (server-only) |

Status: experimental beta. Core user + management + patch + token parity is largely covered in tests; gaps are tracked in [§8](#8-open-gaps-and-recommended-follow-ups).

---

## 2. Intentional OpenAuth extensions

Deliberate capabilities beyond Better Auth 1.6.9.

### 2.1 Routes and resource types

| Feature | OpenAuth | Upstream |
| --- | --- | --- |
| SCIM Groups | CRUD + `POST /Groups/.search` → org teams | Not present |
| Bulk | `POST /scim/v2/Bulk` (`bulkId`, `failOnErrors`, scope checks, `ScimBulkMode`) | Not present (`bulk.supported: false`) |
| `.search` | Users, Groups, combined `/scim/v2/.search` | Not present |
| `GET /scim/v2/Me` | 501 + SCIM error | Not present |

Groups require an **organization-scoped** provider.

### 2.2 Query, concurrency, representation

| Feature | Notes |
| --- | --- |
| Extended filters | `parse_filter` + `resource_matches_filter` on User JSON; Groups in memory |
| SQL pushdown (compat) | Only `userName eq "…"` → `users.email` via `list_user_filter_uses_database_pushdown` |
| Pagination / sort | `startIndex`, `count`, `sortBy`, `sortOrder`; list capped at 200 |
| Projections | `attributes`, `excludedAttributes` (incl. extension URN paths) |
| Weak ETags | `ETag` / `If-Match` on Users and Groups |
| Extension profiles | `scim_user_profiles`, `scim_group_profiles` JSON + metadata schemas |

### 2.3 PATCH and security defaults

- Upstream **ignores** `remove` PatchOps (`src/patch-operations.ts`).
- OpenAuth **implements** `remove` (e.g. `externalId` → reset `account_id` to `userName`) and profile paths (`patch.rs`).
- Default **hashed** tokens; constant-time compare (`subtle`).

---

## 3. Aligned with Better Auth

Same observable behavior unless [§4](#4-divergences-documented) says otherwise.

### 3.1 Provider model

- Plugin id: `scim`.
- Table: `providerId` (globally unique), `scimToken`, optional `organizationId`, optional `userId`.
- Bearer: `base64url(baseToken:providerId[:organizationId])`; org id may contain `:`.
- `providerId` must not contain `:`.

### 3.2 Management (session auth)

| Route | Behavior |
| --- | --- |
| `POST /scim/generate-token` | 201 + `{ scimToken }` |
| `GET /scim/list-provider-connections` | Filtered by org role / ownership |
| `GET /scim/get-provider-connection` | 404 / 403 |
| `POST /scim/delete-provider-connection` | `{ success: true }` |

Default roles: `admin` + org creator role (`owner` unless customized). Empty `requiredRole` → any org member.

Hooks: `beforeSCIMTokenGenerated`, `afterSCIMTokenGenerated`.

Token storage modes: plain, hashed, encrypted, custom (same intent as `src/scim-tokens.ts`).

### 3.3 Users (Bearer)

| Behavior | Upstream ref |
| --- | --- |
| Create / link by email | `createSCIMUser` |
| `accountId` = `externalId` ?? `userName` | `mappings.ts` |
| Duplicate account → 409 `uniqueness` | routes |
| Org token → create `member` if missing | routes |
| Scope by provider + org on list/get/put/patch/delete | `findUserById` |
| PATCH: `/name/*`, `/userName`, `/externalId`; dot paths; idempotent `add` | `patch-operations.ts` |
| List filter (DB): `userName eq` → `email` | `scim-filters.ts` |
| Metadata (User) | `user-schemas.ts`, metadata routes |
| SCIM error envelope | `scim-error.ts` |
| `active: true` on resource | `scim-resources.ts` |
| `defaultSCIM` static providers | `types.ts` / middleware |

### 3.4 DELETE semantics (important)

Upstream Better Auth **deletes the OpenAuth user record** on `DELETE /Users/:id` via `internalAdapter.deleteUser`, even when create linked an existing user by email.

OpenAuth defaults to `ScimDeprovisionMode::UnlinkAccount`: DELETE removes only the current provider account and SCIM profile (and org membership when org-scoped). The global user remains when other accounts exist (password `credential`, other IdPs, or additional SCIM providers).

`ScimDeprovisionMode::DeleteUser` removes the user only when no other linked accounts remain besides the current SCIM provider; otherwise it unlinks like the default mode.

---

## 4. Divergences (documented)

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| Default token storage | `plain` | `Hashed` | Safer production default |
| Token regeneration | delete + create | `upsert` | Stable row id, fewer races |
| Email validation | loose | `validation.rs` on create/put/bulk/patch | Prevent junk identities |
| List filters | `userName eq` only | pushdown + in-memory extended | Enterprise attrs without second DSL |
| ServiceProviderConfig | understates bulk/sort/etag | advertises real support | Honest capability flags |
| Schemas | User only | User + Group + Enterprise | Matches routes |
| Pagination | `startIndex: 1`, full set | `startIndex` / `count` + cap | Large directories |
| PATCH `remove` | ignored | implemented | RFC clients |
| Management errors | `APIError` JSON | OpenAuth core JSON | Same non-SCIM envelope |
| PATCH identical `add` | skip (no-op) | may 400 “No valid fields” | Stricter no-op detection |

---

## 5. What upstream does not ship (and OpenAuth choices)

| Upstream limitation | OpenAuth |
| --- | --- |
| `src/client.ts` | Omitted — server crate only |
| No Groups / Bulk / `.search` | Implemented for IdP conformance |
| Plain default tokens | Hashed default |
| Delete-then-create token rotation | Upsert |
| No strict email validation | Validated |
| Filter = `userName eq` only | Extended in-memory filters |
| No pagination | Pagination + maxResults |
| PATCH `remove` ignored | Supported where safe |
| Dashboard / Infra UI | Out of scope |

---

## 6. Test parity matrix

Legend: ✅ covered · ⚠️ partial · ❌ gap · ➖ N/A

### 6.1 Upstream file → OpenAuth module

| Upstream | OpenAuth tests | Notes |
| --- | --- | --- |
| `src/scim.test.ts` | `routes/metadata.rs`, `metadata.rs`, `routes/users.rs` | ✅ + Group/enterprise metadata |
| `src/scim-users.test.ts` | `routes/users.rs`, `auth.rs`, `organization.rs`, `isolation.rs` | ✅ list/get/delete; item-route isolation added |
| `src/scim-patch.test.ts` | `patch.rs`, `routes/users.rs` | ✅ + remove/profile |
| `src/scim.management.test.ts` | `routes/management.rs`, `organization.rs`, `token.rs` | ⚠️ no TS client test; ⚠️ multi-role comma fixture |
| `src/scim-filters.ts` | `filters.rs` | ✅ + extended parser |
| — | `routes/groups.rs`, `bulk.rs`, `search.rs` | OpenAuth-only |
| — | `validation.rs`, `db_adapters.rs` | OpenAuth-only |

### 6.2 Management scenarios (`scim.management.test.ts`)

| Scenario | Status |
| --- | --- |
| Session required | ✅ |
| Org member / role / GHSA member deny | ✅ |
| Invalid `providerId` (`:`) | ✅ |
| Token storage modes | ✅ |
| Hooks / ownership / cross-org deny | ✅ |
| Custom `requiredRole` / creator role | ✅ |
| Client `generateSCIMToken` | ➖ no TS client |
| User with `role: "admin,member"` | ✅ (`organization.rs`) |

### 6.3 User routes

| Scenario | Status |
| --- | --- |
| Create / put / patch / delete / list / filter | ✅ |
| Provider list isolation | ✅ |
| Provider **item** GET/PUT/PATCH isolation | ✅ (`isolation.rs`) |
| Org list isolation | ✅ |
| Org item GET isolation | ✅ (`isolation.rs`) |
| Token org ≠ row org | ✅ (`isolation.rs`) |
| PUT duplicate `externalId` | ✅ (`isolation.rs`) |
| Default provider | ✅ |

---

## 7. Endpoint inventory

### Better Auth 1.6.9

- Management: `generate-token`, `list-provider-connections`, `get-provider-connection`, `delete-provider-connection`
- Users: CRUD `/scim/v2/Users`
- Metadata: `ServiceProviderConfig`, `Schemas`, `ResourceTypes` (public, User only)

### OpenAuth (additional)

- `POST /scim/v2/Users/.search`
- Groups CRUD + `.search`
- `POST /scim/v2/.search`, `POST /scim/v2/Bulk`
- `GET /scim/v2/Me` → 501

---

## 8. Open gaps and recommended follow-ups

Prioritized from code audit (2026-05).

### P0 — correctness / security tests

| Gap | Recommendation | Status |
| --- | --- | --- |
| Item routes provider isolation | Tests in `tests/scim/routes/isolation.rs` | ✅ added |
| Bearer org suffix ≠ stored `organization_id` | Same | ✅ added |
| PUT duplicate `externalId` same provider | `ensure_provider_account_id_available` on PUT/bulk PUT | ✅ added |
| Shared user DELETE removes all accounts | Default unlink; `DeleteUser` only when sole SCIM account ([§3.4](#34-delete-semantics-important)) | ✅ |

### P1 — tests & parity

| Gap | Recommendation | Status |
| --- | --- | --- |
| Comma-separated org roles (`admin,member`) | Management test mirroring upstream | ✅ `organization.rs` |
| Groups bearer auth battery | Mirror `auth.rs` for `/Groups` | ✅ `groups_auth.rs` |
| Groups without org-scoped provider | Expect 400 on create/list/item | ✅ `groups_scope.rs` |
| `If-Match: *` behavior | Test wildcard accept on Users/Groups | ✅ `concurrency.rs` |
| Bulk PATCH without `If-Match` header | Bulk ignores per-op concurrency headers | ✅ `bulk.rs` |
| PATCH duplicate `externalId` | Same uniqueness as PUT | ✅ `isolation.rs` + handler |
| Link SCIM account to existing user by email | Upstream `scim.test.ts` | ✅ `provisioning.rs` |
| DELETE unlinks provider for shared email | Default + `DeleteUser` guard | ✅ `provisioning.rs`, `deprovision.rs` |
| Groups visible across org providers | Teams are org-scoped, not provider-isolated | ✅ `isolation.rs` |

### P2 — operability

| Gap | Recommendation | Status |
| --- | --- | --- |
| Large directories + in-memory filters | Document: prefer `userName eq` or `.search` with `count` | ✅ README |
| Better Auth plain → OpenAuth hashed migration | Regenerate all provider tokens after upgrade | ✅ README |
| Metadata snapshot tests | Lock schema drift in CI | ✅ `metadata_snapshot.rs` |
| Bulk transactional semantics | `ScimBulkMode::Atomic` + adapter transaction guard | ✅ `bulk.rs`, `db_adapters.rs` |

### P3 — optional product

| Gap | Recommendation | Status |
| --- | --- | --- |
| Composite `(providerId, organizationId)` uniqueness | Deferred — not upstream; use distinct `providerId` values | 📋 documented |
| Configurable deprovision (unlink vs delete) | `ScimDeprovisionMode` | ✅ |
| Audit events | `ScimAuditEventResolver` + logging | ✅ `audit.rs` |
| MongoDB adapter tests | When OpenAuth `DbAdapter` exists | 📋 README (no adapter yet) |

---

## Appendix A — Upstream file map

| Concern | Path under `packages/scim/src/` |
| --- | --- |
| Plugin | `index.ts` |
| Routes | `routes.ts` |
| Middleware | `middlewares.ts` |
| Tokens | `scim-tokens.ts` |
| Filters | `scim-filters.ts` |
| Patch | `patch-operations.ts` |
| Resources | `scim-resources.ts` |
| Schemas | `user-schemas.ts`, `scim-metadata.ts` |
| Errors | `scim-error.ts` |
| Client (not ported) | `client.ts` |
| Tests | `scim.test.ts`, `scim-users.test.ts`, `scim-patch.test.ts`, `scim.management.test.ts` |

## Appendix B — OpenAuth file map

| Concern | Path |
| --- | --- |
| Plugin | `src/lib.rs` |
| Routes | `src/routes.rs`, `src/routes/*.rs` |
| Filters | `src/filters.rs` |
| Patch / validation | `src/patch.rs`, `src/validation.rs` |
| Store / schema | `src/store.rs`, `src/schema.rs` |
| Metadata | `src/metadata.rs` |
| Tests | `tests/scim/**` |

---

*Last updated: deep audit vs Better Auth 1.6.9; see `tests/scim/routes/isolation.rs` for newly added parity-gap tests.*
