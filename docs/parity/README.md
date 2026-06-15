# Upstream parity index

RustAuth tracks behavioral parity against Better Auth **v1.6.9**. Pin and fetch
the upstream snapshot from
[`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).

## Status Symbols

Crate `UPSTREAM.md` files use these symbols in feature and gap tables:

| Symbol | Meaning |
| --- | --- |
| ✅ | Implemented for the stated in-scope server behavior. |
| ⚠️ | Partial parity, known caveat, or behavior covered only for a subset of upstream scope. |
| ❌ | Missing in-scope behavior or coverage that should be implemented or explicitly resolved. |
| ➖ | Not applicable or out of scope for that crate, usually because the behavior is client-only, runtime-specific, or owned by a sibling crate. |
| 🎯 | Intentional RustAuth extension, hardening, or Rust-specific design that differs from Better Auth while preserving the relevant server contract. |

| Audience | Document |
| --- | --- |
| **Library users** (crates.io) | `crates/{crate}/README.md` — short **Better Auth compatibility** blurb |
| **Contributors / parity audits** | `crates/{crate}/UPSTREAM.md` — full parity tables and gaps |

Agent prompts: [`UPSTREAM_SPLIT_PROMPT.md`](./UPSTREAM_SPLIT_PROMPT.md) (move README → UPSTREAM),
[`CRATE_AUDIT_PROMPT.md`](./CRATE_AUDIT_PROMPT.md) (deep audit + refresh UPSTREAM).

| Crate | Upstream reference | Full parity doc |
| --- | --- | --- |
| [`rustauth-core`](../../crates/rustauth-core/UPSTREAM.md) | `@better-auth/core` + `better-auth` server runtime | [UPSTREAM.md](../../crates/rustauth-core/UPSTREAM.md) |
| [`rustauth`](../../crates/rustauth/UPSTREAM.md) | `better-auth` public facade | [UPSTREAM.md](../../crates/rustauth/UPSTREAM.md) |
| [`rustauth-plugins`](../../crates/rustauth-plugins/UPSTREAM.md) | `better-auth/plugins/*` | Contributor doc |
| [`rustauth-oauth`](../../crates/rustauth-oauth/UPSTREAM.md) | `@better-auth/core` → `oauth2/` | Contributor doc |
| [`rustauth-oauth-provider`](../../crates/rustauth-oauth-provider/UPSTREAM.md) | `@better-auth/oauth-provider` | Contributor doc |
| [`rustauth-social-providers`](../../crates/rustauth-social-providers/UPSTREAM.md) | `@better-auth/core` → `social-providers/` | Contributor doc |
| [`rustauth-oidc`](../../crates/rustauth-oidc/UPSTREAM.md) | `@better-auth/sso` → OIDC types/discovery | Contributor doc |
| [`rustauth-sso`](../../crates/rustauth-sso/UPSTREAM.md) | `@better-auth/sso` → SSO routes | Contributor doc |
| [`rustauth-saml`](../../crates/rustauth-saml/UPSTREAM.md) | `@better-auth/sso` → SAML | Contributor doc |
| [`rustauth-scim`](../../crates/rustauth-scim/UPSTREAM.md) | `@better-auth/scim` | Contributor doc |
| [`rustauth-passkey`](../../crates/rustauth-passkey/UPSTREAM.md) | `@better-auth/passkey` | Contributor doc |
| [`rustauth-stripe`](../../crates/rustauth-stripe/UPSTREAM.md) | `@better-auth/stripe` | Contributor doc |
| [`rustauth-i18n`](../../crates/rustauth-i18n/UPSTREAM.md) | `@better-auth/i18n` | Contributor doc |
| [`rustauth-telemetry`](../../crates/rustauth-telemetry/UPSTREAM.md) | `@better-auth/telemetry` | Contributor doc |
| [`rustauth-cli`](../../crates/rustauth-cli/UPSTREAM.md) | `packages/cli` (`auth` npm) | Contributor doc |
| [`rustauth-axum`](../../crates/rustauth-axum/UPSTREAM.md) | `better-auth` HTTP integrations | Contributor doc |
| [`rustauth-sqlx`](../../crates/rustauth-sqlx/UPSTREAM.md) | `@better-auth/kysely-adapter` | Contributor doc |
| [`rustauth-diesel`](../../crates/rustauth-diesel/UPSTREAM.md) | `@better-auth/kysely-adapter` | Contributor doc |
| [`rustauth-tokio-postgres`](../../crates/rustauth-tokio-postgres/UPSTREAM.md) | `@better-auth/kysely-adapter` (Postgres) | Contributor doc |
| [`rustauth-deadpool-postgres`](../../crates/rustauth-deadpool-postgres/UPSTREAM.md) | `@better-auth/kysely-adapter` (Postgres) | Contributor doc |
| [`rustauth-redis`](../../crates/rustauth-redis/UPSTREAM.md) | `@better-auth/redis-storage` | Contributor doc |
| [`rustauth-fred`](../../crates/rustauth-fred/UPSTREAM.md) | `@better-auth/redis-storage` | Fred client backend |

Until migration completes, parity content may still live under
`## Upstream parity` in each README—run `UPSTREAM_SPLIT_PROMPT.md` per crate.

Fetch upstream sources locally:

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected tree: `reference/upstream-src/1.6.9/repository/`.

Do not add intermediate audit checklists or `PARITY.md` stub files.
