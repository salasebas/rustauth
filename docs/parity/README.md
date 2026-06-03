# Upstream parity documentation

Structured parity notes for OpenAuth crates against Better Auth **v1.6.9**
([`reference/upstream-better-auth/VERSION.md`](../reference/upstream-better-auth/VERSION.md)).

Each subdirectory documents one Rust crate (or logical surface): upstream mapping,
behavior, tests, and intentional design differences.

| Crate / surface | Upstream reference | Status |
| --- | --- | --- |
| [`openauth-stripe`](openauth-stripe/README.md) | `@better-auth/stripe` | High server parity; **174** Rust integration tests vs upstream Vitest catalog; gaps G1–G12 closed |
| [`openauth-telemetry`](openauth-telemetry/README.md) | `@better-auth/telemetry` | High server parity; **6** upstream Vitest vs **33** Rust tests (**34** with `oauth`); see [gaps](openauth-telemetry/09-gaps-and-follow-ups.md) |
| [`openauth-passkey`](crates/openauth-passkey/README.md) | `@better-auth/passkey` | **~99%** server parity; **19** upstream Vitest server cases vs **60+** Rust tests; optional `mergeSchema` + legacy `publicKey`-only verify remain |
| [`openauth-oauth`](openauth-oauth/README.md) | `@better-auth/core` → `oauth2/` | **High** client OAuth2 primitives; **57** Rust tests vs **15** upstream `it`; Jun 2026 closeout — [09-parity-closeout](openauth-oauth/09-parity-closeout-2026-06.md) |
| [`openauth-oauth-provider`](openauth-oauth-provider/README.md) | `@better-auth/oauth-provider` | **High** server parity; **261** upstream `it` vs **96** Rust tests; Jun 2026 closeout — see [08-parity-closeout](openauth-oauth-provider/08-parity-closeout-2026-06.md) |
| [`openauth-i18n`](openauth-i18n/README.md) | `@better-auth/i18n` | **High** server-only parity; **15** upstream Vitest vs **64** Rust tests; see [08-closure](openauth-i18n/08-closure.md) |
| [`openauth-fred`](openauth-fred/README.md) | `@better-auth/redis-storage` | **~95%** adapter parity; **15** Rust tests; Fred client + Lua RL; see [10-second-pass](openauth-fred/10-second-pass-findings.md) |
| [`openauth-redis`](openauth-redis/README.md) | `@better-auth/redis-storage` | **~95%** adapter parity; **10** Rust tests; sibling to `openauth-fred`; see [11-gap-closure](openauth-redis/11-gap-closure-status.md) |
| [`openauth-axum`](openauth-axum/README.md) | `better-auth` integrations + `better-call/node` | **High** server HTTP adapter parity; **73** Rust tests vs **5** Vitest in `integrations/`; see [06-gaps](openauth-axum/06-gaps-and-hardening.md) |
| [`openauth-cli`](openauth-cli/README.md) | `packages/cli` (`auth` npm) | **High** server toolchain parity; **~284** upstream Vitest vs **52** Rust integration tests; see [09-parity-closure](openauth-cli/09-parity-closure.md) |
| [`openauth-scim`](openauth-scim/README.md) | `@better-auth/scim` | **High** server parity + Groups/Bulk superset; **~87** upstream Vitest vs **189** Rust tests; see [06-tests](openauth-scim/06-tests.md) |
| [`openauth-oidc`](openauth-oidc/README.md) | `@better-auth/sso` → `packages/sso/src/oidc/` | **High** discovery/types; **26** Rust tests vs **71** upstream `discovery.test.ts`; HTTP flow in `openauth-sso` |
| [`openauth-sso`](openauth-sso/README.md) | `@better-auth/sso` → `routes/sso.ts`, `oidc.test.ts` | **High** OIDC E2E; **22** upstream `it(` audited — [06-tests](openauth-sso/06-tests.md) |

Additional crate parity folders may exist as work-in-progress under `docs/parity/`; the table above lists documented surfaces committed with this index.

Fetch upstream sources locally:

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected tree: `reference/upstream-src/1.6.9/repository/`.
