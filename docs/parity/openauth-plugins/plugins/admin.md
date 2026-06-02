# Parity: admin

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/admin/` |
| OpenAuth | `crates/openauth-plugins/src/admin/` |
| Plugin ID | `admin` |
| Tests | **29** OA / **74** BA |
| Global status | 🟡 **Partial** — full routes; list-users/impersonation test gap |

---

## Endpoints (14 routes)

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/admin/set-role` | ✅ | ✅ |
| GET | `/admin/get-user` | ✅ | ✅ |
| POST | `/admin/create-user` | ✅ | ✅ |
| POST | `/admin/update-user` | ✅ | ✅ |
| GET | `/admin/list-users` | ✅ | ✅ |
| POST | `/admin/list-user-sessions` | ✅ | ✅ |
| POST | `/admin/ban-user` | ✅ | ✅ |
| POST | `/admin/unban-user` | ✅ | ✅ |
| POST | `/admin/impersonate-user` | ✅ | ✅ |
| POST | `/admin/stop-impersonating` | ✅ | ✅ |
| POST | `/admin/revoke-user-session` | ✅ | ✅ |
| POST | `/admin/revoke-user-sessions` | ✅ | ✅ |
| POST | `/admin/remove-user` | ✅ | ✅ |
| POST | `/admin/set-user-password` | ✅ | ✅ |
| POST | `/admin/has-permission` | ✅ | ✅ |

---

## Schema

| Field | Table | OA | BA |
|-------|-------|:--:|:--:|
| `role` | user | ✅ | ✅ |
| `banned`, `banReason`, `banExpires` | user | ✅ | ✅ |
| `impersonatedBy` | session | ✅ | ✅ |

Configurable names via `AdminSchemaOptions`.

---

## Hooks / middleware

| Behavior | OA | BA |
|----------------|:--:|:--:|
| Default role on user create | ✅ | ✅ |
| Block banned user session create | ✅ | ✅ |
| Filter impersonated sessions on list-sessions | ✅ | ✅ |
| Permission check per route | ✅ | ✅ |

---

## Options

| Option | OA | BA | Status |
|--------|:--:|:--:|--------|
| `defaultRole` | ✅ | ✅ | ✅ |
| `adminRoles` | ✅ | ✅ | ✅ |
| `roles` + access control | ✅ | ✅ | ✅ |
| `bannedUserMessage` | ✅ | ✅ | ✅ |
| `adminUserIds` bypass | 🟡 | ✅ | Verify |
| `impersonationSessionDuration` | 🟡 | ✅ | Verify |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `parity.rs` | 11 | Named BA scenarios |
| `mod.rs` | 6 | Basic admin CRUD |
| `access_control.rs` | 5 | RBAC |
| `body_validation.rs` | 4 | Input validation |
| `openapi.rs` | 2 | OpenAPI |
| `permissions.rs` | 1 | has-permission |

---

## Upstream scenarios not covered

1. `list-users` — composite filters (eq, ne, contains, startsWith)
2. `list-users` — multi-field sort and pagination edges
3. Impersonation — full cookie chain and duration
4. Ban with `banExpires` auto-unban
5. Revoke all sessions — user with multi-session
6. Role validation — custom vs default roles

---

## Intentional differences

- Explicit OpenAPI operation IDs (`admin/openapi.rs`)
- Integration with `access` crate module for idiomatic Rust RBAC
