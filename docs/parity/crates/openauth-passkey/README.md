# Parity: `openauth-passkey` ↔ Better Auth `@better-auth/passkey`

Parity documentation between the OpenAuth **server-only** Rust crate and the Better Auth upstream plugin **v1.6.9**.

| Field | Value |
| --- | --- |
| Upstream reference | `reference/upstream-src/1.6.9/repository/packages/passkey/` |
| npm package | `@better-auth/passkey@1.6.9` |
| OpenAuth crate | `crates/openauth-passkey` |
| Optional re-export | `openauth` with feature `passkey` → `openauth::passkey` |
| Scope of this analysis | **Server only** (HTTP, schema, WebAuthn verification, session) |

## Executive summary

| Dimension | Upstream 1.6.9 | OpenAuth `openauth-passkey` |
| --- | --- | --- |
| Packaging | Monorepo `packages/passkey` (server + client in one npm) | Dedicated server-only crate; no TS client |
| HTTP endpoints | 7 routes under `/passkey/*` | **Same 7 routes** (method + path) |
| WebAuthn | `@simplewebauthn/server` | `webauthn-rs` + `PasskeyWebAuthnBackend` trait |
| Challenge state | Core `verification` table + signed cookie | Same (OpenAuth `VerificationStore` + cookie) |
| Estimated server parity | — | **~99%** observable contract; see [07-design-differences.md](./07-design-differences.md) |
| Automated tests | **21** Vitest cases in package (19 server + 2 client) + e2e smoke | **60+** Rust tests (`cargo test -p openauth-passkey`) + `openauth` feature test |

## Index

| Document | Contents |
| --- | --- |
| [01-package-mapping.md](./01-package-mapping.md) | Package, file, and dependency mapping |
| [02-server-endpoints.md](./02-server-endpoints.md) | Routes, middleware, register/auth/management flows |
| [03-configuration.md](./03-configuration.md) | Plugin options side by side |
| [04-schema-storage.md](./04-schema-storage.md) | `passkey` model, fields, persistence |
| [05-error-codes.md](./05-error-codes.md) | Error codes and when they are emitted |
| [06-test-coverage.md](./06-test-coverage.md) | Test inventory and coverage matrix |
| [07-design-differences.md](./07-design-differences.md) | Intentional gaps, out of scope, follow-ups |
| [08-implementation-audit.md](./08-implementation-audit.md) | Line-by-line audit (source + tests) |
| [09-ecosystem-and-edge-cases.md](./09-ecosystem-and-edge-cases.md) | Related plugins, origins, fresh session HTTP, fake vs real backend |

## Related repo documents

- `crates/openauth-passkey/UPSTREAM_PARITY.md` — short crate note (keep aligned with this folder)
- `docs/superpowers/plans/2026-05-17-passkey-server-plugin.md` — original implementation plan
- `reference/upstream-better-auth/VERSION.md` — pinned parity version (1.6.9)

## Table label conventions

| Label | Meaning |
| --- | --- |
| **Aligned** | Same observable server behavior |
| **Design** | Deliberate difference (Rust, server-only, security) |
| **Extension** | OpenAuth does more than upstream on the server |
| **N/A client** | Only in `@better-auth/passkey/client`; not applicable to OpenAuth |
| **Gap** | Upstream behavior not replicated or not tested |
