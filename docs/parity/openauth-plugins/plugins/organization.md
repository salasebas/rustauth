# Parity: organization

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/organization/` |
| OpenAuth | `crates/openauth-plugins/src/organization/` |
| Plugin ID | `organization` |
| Tests | **32** OA / **182** BA `it()` |
| Global status | 🟡 **Partial** — full routes and options (Jun 2026); test depth gap vs upstream |

> `POST /organization/check-slug` exists **in both** (upstream `crud-org.ts`). OpenAuth has a **dedicated test** in `tests/organization/query.rs` (Jun 2026). See [05-third-pass-audit.md](../05-third-pass-audit.md).

---

## Endpoints (33 routes)

Route parity: **✅ Full** — all upstream routes are registered in `organization/routes/`.

### Organization

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/organization/create` | ✅ | ✅ |
| POST | `/organization/update` | ✅ | ✅ |
| POST | `/organization/delete` | ✅ | ✅ |
| POST | `/organization/check-slug` | ✅ | ✅ |
| GET | `/organization/get-full-organization` | ✅ | ✅ |
| GET | `/organization/list` | ✅ | ✅ |
| POST | `/organization/set-active` | ✅ | ✅ |
| POST | `/organization/has-permission` | ✅ | ✅ |

### Members

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/organization/add-member` | ✅ | ✅ |
| POST | `/organization/remove-member` | ✅ | ✅ |
| POST | `/organization/update-member-role` | ✅ | ✅ |
| POST | `/organization/leave` | ✅ | ✅ |
| GET | `/organization/get-active-member` | ✅ | ✅ |
| GET | `/organization/list-members` | ✅ | ✅ |
| GET | `/organization/get-active-member-role` | ✅ | ✅ |

### Invitations

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/organization/invite-member` | ✅ | ✅ |
| POST | `/organization/accept-invitation` | ✅ | ✅ |
| POST | `/organization/reject-invitation` | ✅ | ✅ |
| POST | `/organization/cancel-invitation` | ✅ | ✅ |
| GET | `/organization/get-invitation` | ✅ | ✅ |
| GET | `/organization/list-invitations` | ✅ | ✅ |
| GET | `/organization/list-user-invitations` | ✅ | ✅ |

### Teams

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/organization/create-team` | ✅ | ✅ |
| POST | `/organization/remove-team` | ✅ | ✅ |
| POST | `/organization/update-team` | ✅ | ✅ |
| POST | `/organization/set-active-team` | ✅ | ✅ |
| GET | `/organization/list-teams` | ✅ | ✅ |
| GET | `/organization/list-user-teams` | ✅ | ✅ |
| GET | `/organization/list-team-members` | ✅ | ✅ |
| POST | `/organization/add-team-member` | ✅ | ✅ |
| POST | `/organization/remove-team-member` | ✅ | ✅ |

### Roles (dynamic access control)

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/organization/create-role` | ✅ | ✅ |
| POST | `/organization/delete-role` | ✅ | ✅ |
| GET | `/organization/list-roles` | ✅ | ✅ |
| GET | `/organization/get-role` | ✅ | ✅ |
| POST | `/organization/update-role` | ✅ | ✅ |

---

## Schema

| Entity | Upstream | OpenAuth | Status |
|---------|----------|----------|--------|
| `organization` | ✅ | ✅ | Full |
| `member` | ✅ | ✅ | Full |
| `invitation` | ✅ | ✅ | Full |
| `team` | ✅ (optional) | ✅ | Full |
| `teamMember` | ✅ | ✅ | Full |
| `organizationRole` | ✅ (dynamic AC) | ✅ | Full |
| Session `activeOrganizationId` | ✅ | ✅ | Full |
| Session `activeTeamId` | ✅ | ✅ | Full |
| Org `metadata` | `string` (serialized JSON) | `serde_json::Value` | 🎯 Intentional |

---

## Hooks

| Upstream hook | OpenAuth | Status |
|---------------|----------|--------|
| before/after create/update/delete org | `organization/hooks.rs` | ✅ |
| before/after add/remove member | ✅ | ✅ |
| before/after invitation lifecycle | ✅ | ✅ |
| before/after team CRUD | ✅ | ✅ |
| beforeCreateRole / afterCreateRole (etc.) | — | 🟡 Partial vs upstream role-hook matrix |

---

## Configuration options

| Option | Upstream | OpenAuth | Status | Notes |
|--------|----------|----------|--------|-------|
| `ac` + `roles` | Injectable AC instance | `access_control`, `roles`, `custom_roles` | ✅ | Jun 2026 |
| `allowUserToCreateOrganization` | `bool \| async fn` | `bool` | 🟡 | Async callback not ported |
| `organizationLimit` | `number \| async fn` | `OrganizationLimit` (fixed or callback) | ✅ | Jun 2026 |
| `membershipLimit` | `number \| async fn(user, org)` | `MembershipLimit` (fixed or callback) | ✅ | Jun 2026 |
| `teams.enabled` | ✅ | ✅ | ✅ | |
| `teams.maximumTeams` | optional fn | static flags | 🟡 | |
| `teams.customCreateDefaultTeam` | callback | `TeamOptions::custom_create_default_team` | ✅ | Jun 2026 |
| `dynamicAccessControl` | ✅ | ✅ | ✅ | |
| `sendInvitationEmail` | ✅ | ✅ | ✅ | |
| `cancelPendingInvitationsOnReInvite` | ✅ | ✅ | ✅ | |
| `requireEmailVerificationOnInvitation` | ✅ | ✅ | ✅ | |
| `disableOrganizationDeletion` | ✅ | ✅ | ✅ | |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `mod.rs` | 9 | Basic CRUD, default permissions |
| `hooks.rs` | 4 | Lifecycle hooks |
| `teams.rs` | 2 | Teams + capacity |
| `dynamic_access_control.rs` | 2 | Dynamic roles |
| `additional_fields.rs` | 5 | Extra org/member fields |
| `query.rs` | 6 | Pagination/listings + **check-slug** |
| `limits.rs` | 3 | Async organization/membership limits |
| `session.rs` | 4 | active org/team on session |
| `openapi.rs` | 1 | Operation IDs |

---

## Upstream scenarios not yet covered (priority)

1. Exhaustive multi-role permission matrices
2. Re-invite with cancel pending invitations — combinatorics
3. Cross-org isolation under load
4. `disableOrganizationDeletion` enforcement matrix
5. Custom AC with non-default statements
6. Last-owner removal edge cases

---

## Intentional differences

- Explicit `Result` errors vs `APIError` throw
- `metadata` as structured JSON in API
- `request_is_external()` guard for server-only operations with explicit `userId`
