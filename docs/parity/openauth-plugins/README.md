# Parity: `openauth-plugins` vs Better Auth upstream

Parity documentation between the **`openauth-plugins`** crate and Better Auth **v1.6.9** server-side plugins (`f484269`).

## Scope

| Included | Excluded |
|----------|----------|
| Server-side behavior (HTTP routes, hooks, schema, options) | `client.ts` exports and type-inference helpers |
| `@better-auth/api-key` plugin (separate upstream package) | `oidc-provider` plugin → `openauth-oauth-provider` crate |
| Server-side utilities (`access`, `additional-fields` server contribution) | Upstream `test-utils` (test tooling, not a production plugin) |
| Intentional design decisions (Rust, server-only) | Electron, Expo, DB adapters, Stripe, SSO, SCIM (own crates) |

## Upstream reference

```text
reference/upstream-src/1.6.9/repository/
├── packages/better-auth/src/plugins/     # 26 plugins + test-utils
└── packages/api-key/                     # api-key (separate monorepo package)
```

OpenAuth consolidates **27 modules** in one crate. Upstream splits `api-key` into its own npm package and keeps `oidc-provider` inside `better-auth` (deprecated → `@better-auth/oauth-provider`).

## Executive summary

| Metric | OpenAuth | Upstream (server-relevant) |
|--------|----------|----------------------------|
| Supported server plugins | 27 | 27 (+ `oidc-provider` replaced) |
| Integration tests (`tests/<plugin>/`) | **610** | **986** `it()` *(excl. test-utils, oidc-provider; ~1202 incl. describe)* |
| Total HTTP routes (approx.) | ~130 | ~130 |
| Route parity | High — point gaps closed Jun 2026 | — |
| Test parity | Partial — large gap in org, api-key, email-otp | — |

**Overall status:** Routes aligned; path-less upstream APIs materialized as HTTP where needed. **June 2026 parity work closed** server gaps for `generateTOTP`, organization options (`ac`, async limits, `customCreateDefaultTeam`, check-slug test), api-key (`defaultPermissions` callback, schema merge), two-factor custom OTP storage, jwt/phone-number/username schema options, and `verification.storeIdentifier: hashed` in **openauth-core** (used by generic OAuth). Remaining work is mostly **test depth** upstream vs OpenAuth. See [05-third-pass-audit.md](./05-third-pass-audit.md) and the closure checklist in [06-plugin-master-map.md](./06-plugin-master-map.md).

## Document index

| Document | Contents |
|----------|----------|
| [00-package-mapping.md](./00-package-mapping.md) | How upstream packages map to Rust modules |
| [01-comparison-matrix.md](./01-comparison-matrix.md) | Plugin-by-plugin matrix (routes, schema, hooks, tests, status) |
| [02-test-coverage.md](./02-test-coverage.md) | Test counts and covered vs missing scenarios |
| [03-out-of-scope.md](./03-out-of-scope.md) | oidc-provider, client-only, test-utils |
| [04-deep-audit-findings.md](./04-deep-audit-findings.md) | Second pass: code + tests |
| [05-third-pass-audit.md](./05-third-pass-audit.md) | Third pass: options, rate limits, corrections |
| [06-plugin-master-map.md](./06-plugin-master-map.md) | **Master map for 26 plugins** (endpoints, schema, hooks, gaps) |
| [plugins/](./plugins/) | Detailed per-plugin or group analysis |

### Detailed per-plugin analysis

| Plugin / group | File |
|----------------|------|
| organization | [plugins/organization.md](./plugins/organization.md) |
| api-key | [plugins/api-key.md](./plugins/api-key.md) |
| email-otp | [plugins/email-otp.md](./plugins/email-otp.md) |
| two-factor | [plugins/two-factor.md](./plugins/two-factor.md) |
| admin | [plugins/admin.md](./plugins/admin.md) |
| generic-oauth | [plugins/generic-oauth.md](./plugins/generic-oauth.md) |
| phone-number | [plugins/phone-number.md](./plugins/phone-number.md) |
| jwt | [plugins/jwt.md](./plugins/jwt.md) |
| Auth flows (anonymous, magic-link, username, siwe, one-tap, device-auth) | [plugins/auth-flows.md](./plugins/auth-flows.md) |
| Hooks and utilities | [plugins/hooks-and-utilities.md](./plugins/hooks-and-utilities.md), [plugins/utilities.md](./plugins/utilities.md) |
| mcp | [plugins/mcp.md](./plugins/mcp.md) |

## Status conventions

| Status | Meaning |
|--------|---------|
| **Full** | Complete server-side parity or cosmetic-only differences |
| **Partial** | Routes/schema present; gaps in options, secondary hooks, or tests |
| **Missing** | Server functionality absent |
| **N/A** | Out of scope (client-only, other crate) |
| **Intentional** | Documented difference by Rust/server-only design |

## Maintenance

- Upstream version: `reference/upstream-better-auth/VERSION.md`
- Inventory test: `crates/openauth-plugins/tests/plugins.rs` (`upstream_server_plugin_parity_is_explicit_about_replaced_oidc_provider`)
- Crate parity notes: `crates/openauth-plugins/SERVER_PARITY.md`
