# Upstream parity index

OpenAuth tracks behavioral parity against Better Auth **v1.6.9**. Pin and fetch
the upstream snapshot from
[`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).

| Audience | Document |
| --- | --- |
| **Library users** (crates.io) | `crates/{crate}/README.md` — short **Better Auth compatibility** blurb |
| **Contributors / parity audits** | `crates/{crate}/UPSTREAM.md` — full parity tables and gaps |

Agent prompts: [`UPSTREAM_SPLIT_PROMPT.md`](./UPSTREAM_SPLIT_PROMPT.md) (move README → UPSTREAM),
[`CRATE_AUDIT_PROMPT.md`](./CRATE_AUDIT_PROMPT.md) (deep audit + refresh UPSTREAM).

| Crate | Upstream reference | Full parity doc |
| --- | --- | --- |
| [`openauth-core`](../../crates/openauth-core/UPSTREAM.md) | `@better-auth/core` + `better-auth` server runtime | [UPSTREAM.md](../../crates/openauth-core/UPSTREAM.md) |
| [`openauth`](../../crates/openauth/UPSTREAM.md) | `better-auth` public facade | Contributor doc |
| [`openauth-plugins`](../../crates/openauth-plugins/UPSTREAM.md) | `better-auth/plugins/*` | Contributor doc |
| [`openauth-oauth`](../../crates/openauth-oauth/UPSTREAM.md) | `@better-auth/core` → `oauth2/` | Contributor doc |
| [`openauth-oauth-provider`](../../crates/openauth-oauth-provider/UPSTREAM.md) | `@better-auth/oauth-provider` | Contributor doc |
| [`openauth-social-providers`](../../crates/openauth-social-providers/UPSTREAM.md) | `@better-auth/core` → `social-providers/` | Contributor doc |
| [`openauth-oidc`](../../crates/openauth-oidc/UPSTREAM.md) | `@better-auth/sso` → OIDC types/discovery | Contributor doc |
| [`openauth-sso`](../../crates/openauth-sso/UPSTREAM.md) | `@better-auth/sso` → SSO routes | Contributor doc |
| [`openauth-saml`](../../crates/openauth-saml/UPSTREAM.md) | `@better-auth/sso` → SAML | Contributor doc |
| [`openauth-scim`](../../crates/openauth-scim/UPSTREAM.md) | `@better-auth/scim` | Contributor doc |
| [`openauth-passkey`](../../crates/openauth-passkey/UPSTREAM.md) | `@better-auth/passkey` | Contributor doc |
| [`openauth-stripe`](../../crates/openauth-stripe/UPSTREAM.md) | `@better-auth/stripe` | Contributor doc |
| [`openauth-i18n`](../../crates/openauth-i18n/UPSTREAM.md) | `@better-auth/i18n` | Contributor doc |
| [`openauth-telemetry`](../../crates/openauth-telemetry/UPSTREAM.md) | `@better-auth/telemetry` | Contributor doc |
| [`openauth-cli`](../../crates/openauth-cli/UPSTREAM.md) | `packages/cli` (`auth` npm) | Contributor doc |
| [`openauth-axum`](../../crates/openauth-axum/UPSTREAM.md) | `better-auth` HTTP integrations | Contributor doc |
| [`openauth-sqlx`](../../crates/openauth-sqlx/UPSTREAM.md) | `@better-auth/kysely-adapter` | Contributor doc |
| [`openauth-tokio-postgres`](../../crates/openauth-tokio-postgres/UPSTREAM.md) | `@better-auth/kysely-adapter` (Postgres) | Contributor doc |
| [`openauth-deadpool-postgres`](../../crates/openauth-deadpool-postgres/UPSTREAM.md) | `@better-auth/kysely-adapter` (Postgres) | Contributor doc |
| [`openauth-redis`](../../crates/openauth-redis/UPSTREAM.md) | `@better-auth/redis-storage` | Contributor doc |
| [`openauth-fred`](../../crates/openauth-fred/UPSTREAM.md) | `@better-auth/redis-storage` | Fred client backend |

Until migration completes, parity content may still live under
`## Upstream parity` in each README—run `UPSTREAM_SPLIT_PROMPT.md` per crate.

Fetch upstream sources locally:

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected tree: `reference/upstream-src/1.6.9/repository/`.

Do not add intermediate audit checklists or `PARITY.md` stub files.
