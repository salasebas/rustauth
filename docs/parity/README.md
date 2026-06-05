# Upstream parity index

OpenAuth tracks behavioral parity against Better Auth **v1.6.9**. Pin and fetch
the upstream snapshot from
[`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).

Each crate documents its own status in **Upstream parity (Better Auth 1.6.9)**
inside its README. This page is only an index.

| Crate | Upstream reference | Parity notes |
| --- | --- | --- |
| [`openauth-core`](../../crates/openauth-core/README.md#upstream-parity-better-auth-169) | `@better-auth/core` + `better-auth` server runtime | High server parity; see crate README |
| [`openauth`](../../crates/openauth/README.md#upstream-parity-better-auth-169) | `better-auth` public facade | Re-exports core + optional integrations |
| [`openauth-plugins`](../../crates/openauth-plugins/README.md#upstream-parity-better-auth-169) | `better-auth/plugins/*` | High server parity for shipped plugins |
| [`openauth-oauth`](../../crates/openauth-oauth/README.md#upstream-parity-better-auth-169) | `@better-auth/core` → `oauth2/` | High client OAuth2 primitives |
| [`openauth-oauth-provider`](../../crates/openauth-oauth-provider/README.md#upstream-parity-better-auth-169) | `@better-auth/oauth-provider` | High OAuth 2.1 / OIDC provider parity |
| [`openauth-social-providers`](../../crates/openauth-social-providers/README.md#upstream-parity-better-auth-169) | `@better-auth/core` → `social-providers/` | Provider catalog parity |
| [`openauth-oidc`](../../crates/openauth-oidc/README.md#upstream-parity-better-auth-169) | `@better-auth/sso` → OIDC types/discovery | High discovery and type parity |
| [`openauth-sso`](../../crates/openauth-sso/README.md#upstream-parity-better-auth-169) | `@better-auth/sso` → SSO routes | High OIDC HTTP flow parity |
| [`openauth-saml`](../../crates/openauth-saml/README.md#upstream-parity-better-auth-169) | `@better-auth/sso` → SAML | Experimental; see crate README |
| [`openauth-scim`](../../crates/openauth-scim/README.md#upstream-parity-better-auth-169) | `@better-auth/scim` | High server parity + extensions |
| [`openauth-passkey`](../../crates/openauth-passkey/README.md#upstream-parity-better-auth-169) | `@better-auth/passkey` | High WebAuthn server parity |
| [`openauth-stripe`](../../crates/openauth-stripe/README.md#upstream-parity-better-auth-169) | `@better-auth/stripe` | High billing plugin parity |
| [`openauth-i18n`](../../crates/openauth-i18n/README.md#upstream-parity-better-auth-169) | `@better-auth/i18n` | High server-only i18n parity |
| [`openauth-telemetry`](../../crates/openauth-telemetry/README.md#upstream-parity-better-auth-169) | `@better-auth/telemetry` | High telemetry payload parity |
| [`openauth-cli`](../../crates/openauth-cli/README.md#upstream-parity-better-auth-169) | `packages/cli` (`auth` npm) | High CLI/tooling parity |
| [`openauth-axum`](../../crates/openauth-axum/README.md#upstream-parity-better-auth-169) | `better-auth` HTTP integrations | High Axum adapter parity |
| [`openauth-sqlx`](../../crates/openauth-sqlx/README.md#upstream-parity-better-auth-169) | `@better-auth/kysely-adapter` | SQL adapter parity |
| [`openauth-tokio-postgres`](../../crates/openauth-tokio-postgres/README.md#upstream-parity-better-auth-169) | `@better-auth/kysely-adapter` (Postgres) | Minimal Postgres client adapter |
| [`openauth-deadpool-postgres`](../../crates/openauth-deadpool-postgres/README.md#upstream-parity-better-auth-169) | `@better-auth/kysely-adapter` (Postgres) | Pooled Postgres adapter |
| [`openauth-redis`](../../crates/openauth-redis/README.md#upstream-parity-better-auth-169) | `@better-auth/redis-storage` | Redis secondary storage + rate limits |
| [`openauth-fred`](../../crates/openauth-fred/README.md#upstream-parity-better-auth-169) | `@better-auth/redis-storage` | Same upstream; Fred client backend |

Fetch upstream sources locally:

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected tree: `reference/upstream-src/1.6.9/repository/`.

When porting or closing gaps, update the crate README **Upstream parity** section
using this shape:

- **Status** — upstream package, parity level, test counts
- **Intentional differences** — Rust/OpenAuth choices that diverge from upstream
- **Open gaps / risks** — missing behavior, shallow tests, production caveats
- **Upstream lookup** — how to find the matching upstream package and tests

Do not add intermediate audit checklists or standalone `PARITY.md` files to this
repository.
