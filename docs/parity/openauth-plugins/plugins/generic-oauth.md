# Parity: generic-oauth

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/generic-oauth/` |
| OpenAuth | `crates/openauth-plugins/src/generic_oauth/` |
| Plugin ID | `generic-oauth` |
| Tests | **41** OA / **68** BA |
| Global status | 🟡 **Partial** — full routes; CSRF/state test gap |

---

## Endpoints (3 routes)

| Method | Route | OA | BA |
|--------|------|:--:|:--:|
| POST | `/sign-in/oauth2` | ✅ | ✅ |
| GET | `/oauth2/callback/:providerId` | ✅ | ✅ |
| POST | `/oauth2/link` | ✅ | ✅ |

---

## Provider presets

Upstream and OpenAuth include presets under `providers/`:

| Provider | OA | BA |
|----------|:--:|:--:|
| Auth0 | ✅ | ✅ |
| Okta | ✅ | ✅ |
| Keycloak | ✅ | ✅ |
| Microsoft Entra | ✅ | ✅ |
| Slack | ✅ | ✅ |
| Line | ✅ | ✅ |
| HubSpot, Patreon, Gumroad, … | Partial | ✅ |

---

## Schema

Uses core `account` table — no dedicated plugin schema. **✅ Full**

---

## Hooks / flow

| Aspect | OA | BA | Status |
|---------|:--:|:--:|--------|
| PKCE | ✅ | ✅ | ✅ |
| Discovery URL | ✅ | ✅ | ✅ |
| Issuer validation | ✅ | ✅ | ✅ |
| State cookie CSRF | ✅ | ✅ | 🟡 tests |
| Implicit linking | `trusted_providers` | `trustedProviders` | 🎯 static only |
| `mapProfileToUser` | ✅ | ✅ | ✅ |

---

## Options

| Option | OA | BA |
|--------|:--:|:--:|
| `config[]` multi-provider | ✅ | ✅ |
| `providerId`, clientId/secret | ✅ | ✅ |
| `pkce`, scopes | ✅ | ✅ |
| `requireIssuerValidation` | ✅ | ✅ |
| Discovery / authorization URLs | ✅ | ✅ |

---

## `storeIdentifier: hashed`

Upstream tests use hashed verification identifiers (`generic-oauth.test.ts`). OpenAuth implements this via **`openauth-core`** `verification.store_identifier` ✅ — not a field on `generic_oauth` config. Configure at auth builder / `OpenAuthOptions` level.

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `routes.rs` | 29 | callback, state, sign-in |
| `provider.rs` | 6 | presets |
| `plugin.rs` | 4 | plugin registration |
| `helpers.rs` | 2 | utilities |

---

## Upstream scenarios not covered

1. Cookie-backed OAuth state tampering
2. Full issuer mismatch/missing matrix
3. Implicit sign-up on first OAuth login
4. `newUserCallbackURL` redirects
5. Link-account with existing session
6. E2E per preset provider (token + userinfo mocks)

---

## Intentional differences

Documented in `SERVER_PARITY.md`:

| Topic | Detail |
|------|---------|
| `trusted_providers` | Static; upstream allows dynamic per-request resolution |
| Implicit linking | Same trust rule as one-tap and core social OAuth |
