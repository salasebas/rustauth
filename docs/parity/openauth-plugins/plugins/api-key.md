# Parity: api-key

| Field | Value |
|-------|-------|
| Upstream | **`packages/api-key/`** (npm `@better-auth/api-key`, separate from `better-auth`) |
| OpenAuth | `crates/openauth-plugins/src/api_key/` |
| Plugin ID | `api-key` |
| Tests | **52** OA / **176** BA `it()` |
| Global status | 🟡 **Partial** — functional parity; verify/delete-expired as explicit HTTP; options closed Jun 2026 |

> Upstream registers `verifyApiKey` and `deleteAllExpiredApiKeys` as **path-less** (`createAuthEndpoint({ method })`). OpenAuth exposes `POST /api-key/verify` and `POST /api-key/delete-all-expired-api-keys`. Equivalent behavior; more explicit REST surface.

> Upstream packages api-key as a separate npm package. OpenAuth integrates it into `openauth-plugins` for a unified server plugins crate.

---

## Endpoints (7 routes)

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/api-key/create` | ✅ | ✅ |
| POST | `/api-key/verify` | ✅ | ✅ |
| GET | `/api-key/get` | ✅ | ✅ |
| POST | `/api-key/update` | ✅ | ✅ |
| POST | `/api-key/delete` | ✅ | ✅ |
| GET | `/api-key/list` | ✅ | ✅ |
| POST | `/api-key/delete-all-expired-api-keys` | ✅ | ✅ |

---

## Schema

| Field / aspect | Upstream | OpenAuth | Status |
|-----------------|----------|----------|--------|
| Model name | `apikey` | `api_key` | 🎯 Intentional |
| Table default | `apikey` | `api_keys` | 🎯 Intentional |
| `configId` | ✅ | ✅ | ✅ |
| `prefix`, hashed key | ✅ | ✅ | ✅ |
| `referenceId` (user/org) | ✅ | ✅ | ✅ |
| Rate limit fields | ✅ | ✅ | ✅ |
| `remaining`, refill | ✅ | ✅ | ✅ |
| `permissions`, metadata | ✅ | ✅ | ✅ |
| Expiration | ✅ | ✅ | ✅ |

---

## Hooks

| Hook | Upstream | OpenAuth | Status |
|------|----------|----------|--------|
| `before` — API key header → session | ✅ | `with_async_before_hook("*")` | ✅ |
| `enableSessionForAPIKeys` | ✅ | ✅ | ✅ |
| Org-owned key + org permissions | ✅ | `api_key/organization.rs` | ✅ |
| `validateApiKey` helper | ✅ | ✅ | ✅ |

---

## Options

| Option | OA | BA | Status |
|--------|:--:|:--:|--------|
| Multi-`configId` | ✅ | ✅ | ✅ |
| `customAPIKeyGetter` | ✅ | ✅ | ✅ |
| `customAPIKeyValidator` | ✅ | ✅ | ✅ |
| `storage`: database / secondary | ✅ | ✅ | ✅ |
| `fallbackToDatabase` | ✅ | ✅ | ✅ |
| `deferUpdates` | ✅ | ✅ | ✅ |
| Hashing custom | ✅ | ✅ | ✅ |
| `defaultPermissions` callback per config | ✅ | ✅ | ✅ Jun 2026 |
| Schema merge at build (`with_schema`, `api_key_with_build`) | ✅ | ✅ | ✅ Jun 2026 |
| Org authorization | ✅ | ✅ | ✅ |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `lifecycle.rs` | 15 | create/update/delete/expire |
| `storage.rs` | 11 | DB vs secondary storage |
| `verify.rs` | 9 | verify + permissions |
| `sessions.rs` | 7 | enableSessionForAPIKeys |
| `surface.rs` | 3 | API surface |
| `metadata.rs` | 2 | metadata JSON |
| `configurations.rs` | 2 | multi-configId |
| `organization.rs` | 2 | org-owned keys |
| `schema.rs` | 1 | schema contribution |

---

## Upstream scenarios not covered

1. Rate limit windows with mocked time (vitest fake timers)
2. `remaining` refill under concurrent requests
3. Secondary storage failure + fallback matrix
4. Multi-configId edge cases (different headers per config)
5. Mass expired cleanup under concurrency
6. Clock skew on expiration

---

## Intentional differences

| Topic | Detail |
|------|---------|
| Table naming | `api_keys` vs `apikey` — OpenAuth adapters use snake_case convention |
| Errors | Rust `ApiKeyError` vs `API_KEY_ERROR_CODES` objects |
| Secondary listing | README documents multi-process limitation without DB fallback |

## OpenAuth extensions (not upstream)

| Feature | Detail |
|---------|--------|
| `revalidate_secondary_against_database` | Implemented + `storage.rs` tests |
| `defer_updates` | Implemented + `verify.rs`, `storage.rs` tests |

## Operational note

In pure `SecondaryStorage` mode, the `api-key:by-ref:*` index uses an in-process lock. Multi-process deployments need an atomic backend or DB fallback for consistent `/api-key/list`.
