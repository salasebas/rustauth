# Paridad: `openauth-sso` (flujo OIDC HTTP) ↔ `@better-auth/sso`

Documentación de paridad **solo servidor** para el plugin SSO de OpenAuth frente a Better Auth **v1.6.9**, con foco en el flujo OIDC relying party (registro, sign-in, callback, provisioning).

| Campo | Valor |
| --- | --- |
| Upstream npm | `@better-auth/sso@1.6.9` |
| Upstream rutas + E2E | `packages/sso/src/routes/sso.ts`, `packages/sso/src/oidc.test.ts` |
| Crate Rust | `crates/openauth-sso` (feature `oidc`) |
| Discovery / tipos OIDC | [`openauth-oidc`](../openauth-oidc/README.md) |
| Paridad pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |

## Relación de paquetes

| Rol | Upstream | OpenAuth |
| --- | --- | --- |
| Plugin SSO (HTTP, DB, callback) | `@better-auth/sso` | `openauth-sso` |
| Discovery OIDC RP | `packages/sso/src/oidc/*` | `openauth-oidc` |
| SAML | mismo paquete npm | `openauth-saml` + feature en SSO |
| Cliente tipado | `@better-auth/sso/client` | **No portado** |

## Índice

| Documento | Contenido |
| --- | --- |
| [01-overview.md](./01-overview.md) | Alcance, frontera con `openauth-oidc`, estado resumido |
| [06-tests.md](./06-tests.md) | Matriz `oidc.test.ts` (22 escenarios) ↔ tests Rust |

## Verificación rápida

```bash
cargo fmt --all --check
cargo clippy -p openauth-sso --all-targets --features oidc -- -D warnings
cargo nextest run -p openauth-sso --test sso
```

| Métrica | Upstream | `openauth-sso` (OIDC) |
| --- | --- | --- |
| E2E OIDC | `oidc.test.ts` — **22** `it(` | Integration bajo `tests/sso/endpoints/` + `oidc_upstream_parity.rs` |
| Discovery Vitest | `oidc/discovery.test.ts` — **71** | Ver [`openauth-oidc/05-tests.md`](../openauth-oidc/05-tests.md) |

Última auditoría documentada: **2026-06-01** (Better Auth `v1.6.9`).
