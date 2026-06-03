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

Additional crate parity folders may exist as work-in-progress under `docs/parity/`; the table above lists documented surfaces committed with this index.

Fetch upstream sources locally:

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected tree: `reference/upstream-src/1.6.9/repository/`.
