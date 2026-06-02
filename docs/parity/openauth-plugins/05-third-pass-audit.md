# Third pass: additional findings (code + tests)

Audit after [04-deep-audit-findings.md](./04-deep-audit-findings.md). Only **new or corrected** items appear here.

**June 2026 closure:** functional gaps listed in the “options / behavior gaps” section below were addressed in code; this doc records the audit baseline and closure status.

---

## Important correction: `check-slug`

**Error in 04:** `POST /organization/check-slug` was documented as OpenAuth-only.

**Upstream 1.6.9 reality:** exists in `organization/routes/crud-org.ts` (`checkOrganizationSlug`), method **POST**, body `{ slug }`, response `{ status: true }` or error `ORGANIZATION_SLUG_ALREADY_TAKEN`.

| | Upstream | OpenAuth |
|---|:--------:|:--------:|
| Route | `POST /organization/check-slug` | ✅ Same |
| Upstream test | `should check if organization slug is available` | ✅ Rust test Jun 2026 |

---

## Options / behavior gaps (audit baseline → Jun 2026 status)

### Organization

| Upstream field / behavior | OpenAuth (audit) | Jun 2026 |
|---------------------------|------------------|----------|
| Injectable `ac?: AccessControl` | Was missing — `custom_roles` only | ✅ `access_control`, `roles` |
| `membershipLimit` / `organizationLimit` async fn | Was sync only | ✅ `OrganizationLimit` / `MembershipLimit` callbacks |
| `allowUserToCreateOrganization` as function | `bool` only | 🟡 Still `bool` |
| `teams.defaultTeam.customCreateDefaultTeam` | Was absent | ✅ `custom_create_default_team` |
| `schema.session.fields` (rename `activeOrganizationId`) | Was absent | 🟡 Still absent on `OrganizationSchemaOptions` |
| `organizationHooks` **async** | Sync `Arc<dyn Fn -> Result>` | 🟡 Documented Rust limitation |
| Merge DB permissions + `ac.newRole()` | Static + JSON `custom_roles` | 🟡 Partial vs upstream `has-permission.ts` |
| `MISSING_AC_INSTANCE` code | Defined, never returned | 🟡 Unchanged |

**Partially aligned:** `RoleInput::Many(Vec<String>)` for multi-role invites/members (`organization/routes/input.rs`) — upstream has explicit tests not all ported.

### API key

| Upstream field | OpenAuth (audit) | Jun 2026 |
|--------------|------------------|----------|
| `permissions.defaultPermissions` callback | Was static | ✅ Callback on create |
| `ApiKeyOptions.schema` + `mergeSchema` | Fixed default | ✅ `with_schema`, build-time merge |
| — | `revalidate_secondary_against_database` | ✅ OA extension |
| — | `defer_updates` | ✅ OA extension |

### Two-factor

| Upstream field | OpenAuth (audit) | Jun 2026 |
|--------------|------------------|----------|
| `otpOptions.storeOTP` custom hash/encrypt | Enum only | ✅ `CustomHash`, `CustomEncrypt` |
| Full `schema?` (additionalFields) | `two_factor_table` string only | 🟡 Table name configurable |
| Plugin rate limit | Hardcoded `/two-factor/*` | 🟡 Unchanged (not in options) |

### JWT, phone-number, username

| Plugin | Upstream `schema?` | Jun 2026 |
|--------|-------------------|----------|
| jwt | Rename JWKS table/fields | ✅ Schema options |
| phone-number | Rename `phoneNumber` fields | ✅ Schema options |
| username | Rename username fields | ✅ Schema options |

### Generic OAuth

- **`storeIdentifier: "hashed"`** — upstream tests in `generic-oauth.test.ts`; implemented via **`openauth-core`** `verification.store_identifier` ✅ (not a `generic_oauth` crate field).

### Captcha

- **CaptchaFox** provider in OpenAuth (`captcha/verify_handlers/captchafox.rs`) — parity with upstream captcha.

---

## Hooks: full OpenAuth inventory

| Plugin | Mechanism | Paths / notes |
|--------|-----------|---------------|
| additional_fields | `init` | schema contribution |
| admin | `init`, `async_after` | **`/list-sessions`** (core) |
| anonymous | `init` + link hooks | `/sign-in*`, `/callback*`, … |
| api_key | `async_before` | `*` |
| bearer | `on_request`, `on_response` | — |
| captcha | `async_middleware` | `*` + configured paths |
| custom_session | `async_after` | `/get-session`, optional `/multi-session/list-device-sessions` |
| email_otp | `async_after` | `/sign-up/email`, `/send-verification-email` |
| jwt | `async_after` | `/get-session` → JWT header |
| last_login_method | `init`, `async_after` | `*` |
| mcp | `async_after` | `*` resume login |
| multi_session | `async_after` | `*`, `/sign-out` |
| oauth_proxy | before/after | social + oauth2 + `/callback/:id` |
| one_time_token | `async_after` | `*` OTT header |
| phone_number | `before` | `/update-user` |
| username | `before` | `/sign-up/email`, `/update-user` |
| haveibeenpwned | `password_validator` | configured paths |

**Note:** `custom-session` does **not** override `GET /get-session` — only enriches response in after-hook.

---

## Rate limits (full map)

| Plugin | Rule | Configurable | Default |
|--------|-------|:------------:|---------|
| email_otp | All paths in `registry::paths()` (11) | `EmailOtpOptions.rate_limit` | 60s / 3 |
| magic_link | sign-in + verify | `MagicLinkRateLimit` | in options |
| phone_number | `/phone-number/*` | **No** — hardcoded | 60s / 10 |
| two_factor | `/two-factor/*` | **No** — hardcoded | 10s / 3 |
| api_key | Per key record | `ApiKeyRateLimitOptions` | per config |

---

## Bearer `require_signature` (semantics)

`bearer/request.rs`:

- Token with `.` → verify cookie signature
- No `.` + `require_signature: true` → **ignore** (do not inject session)
- No `.` + `require_signature: false` → **sign** raw token and inject as cookie

Tests: `tests/bearer/options.rs`. Cross-check upstream on upgrade.

---

## OpenAPI audit: exclusions

`tests/open_api/mod.rs::generated_schema_audits_all_server_plugin_endpoints` mounts 16 plugins but **excludes**:

| Excluded | Impact |
|----------|---------|
| **admin** | 15 routes without automatic audit |
| **device_authorization** | 5 routes |
| **generic_oauth** | Only 2 operationIds in separate test |
| captcha, bearer, custom_session, … | No HTTP routes — OK |

---

## email-otp: resend / attempts (implemented)

Contrary to an older “upstream only” gap note, OpenAuth **implements**:

- `ResendStrategy::Reuse | Rotate` — `email_otp/helpers.rs`
- `allowed_attempts` — `helpers.rs` + `tests/email_otp/mod.rs`
- Storage tests: `tests/email_otp/storage.rs` (reuse/rotate, hashed, encrypted)

**Remaining gap:** full upstream-style HTTP matrix + bearer plugin combo in setup.

---

## MCP: registered routes vs metadata

| Route | Upstream `createAuthEndpoint` | OpenAuth |
|------|:----------------------------:|:--------:|
| `/.well-known/oauth-authorization-server` | ✅ | ✅ |
| `/.well-known/oauth-protected-resource` | ✅ | ✅ |
| `/mcp/authorize`, `/token`, `/register`, `/get-session` | ✅ | ✅ |
| `/mcp/userinfo`, `/mcp/jwks` | metadata only | ✅ handlers |
| `/oauth2/consent` | via embedded `oidcProvider` | ✅ |

---

## Upstream `it()` clusters without clear Rust analog

### Organization (182 upstream, 32 OA)

Still thin vs upstream:

- Exhaustive multi-role / last-owner matrices
- Re-invite + email casing combinatorics
- Slug validation matrix on update (check-slug ✅)

### API key (176 vs 52)

- Org-owned keys: OA only **2** tests (`organization.rs`)
- Sort `createdAt` asc/desc: no dedicated suite
- Fake-timer rate-limit: OA has `verification_enforces_rate_limit_window` (approximate)

### Two-factor (55 vs 21)

- `should not expose viewBackupCodes to client` — no dedicated OA test
- Cross-plugin anonymous + magic-link — not in OA

### Username (33 vs 12)

- `displayUsername` validator matrix — partial coverage

---

## Zero debt in src

No `TODO`, `FIXME`, `unimplemented!`, `todo!` in `crates/openauth-plugins/src/`.

---

## Updated priorities (post Jun 2026)

Functional closure checklist: [06-plugin-master-map.md](./06-plugin-master-map.md) — **0 pending server items**.

Remaining work:

1. **Test depth** — organization, api-key, email-otp, two-factor, username
2. **OpenAPI audit** — include admin + device_authorization
3. **Document** permanent limitations (async org hooks, `allowUserToCreateOrganization` fn)
