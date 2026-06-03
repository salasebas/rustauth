# 06 — Tests: `oidc.test.ts` ↔ `openauth-sso`

Recontado desde fuentes, **2026-06-01**. Upstream: `packages/sso/src/oidc.test.ts` (**22** `it(`).

## Conteos Rust (OIDC)

| Área | Ruta | Tests (aprox.) |
| --- | --- | --- |
| Registro | `tests/sso/endpoints/registration/` | basics, discovery, validation |
| Sign-in | `tests/sso/endpoints/sign_in/` | `oidc_basic.rs`, `defaults_discovery.rs` |
| Callback | `tests/sso/endpoints/oidc_callback/` | errors, discovery, provisioning, mapping, id_token, token_auth, … |
| Paridad upstream explícita | `tests/sso/endpoints/oidc_upstream_parity.rs` | **6** |
| Provider update | `tests/sso/endpoints/provider_update.rs` | incl. empty endpoint → discovery |
| Redirect helpers | `tests/sso/oidc.rs` | 3 (duplican `openauth-oidc/tests/flow.rs`) |

```bash
cargo nextest run -p openauth-sso --test sso
```

## Matriz: `oidc.test.ts` → cobertura OpenAuth

Leyenda: **≈** cubierto · **NEW** = `oidc_upstream_parity.rs` (2026-06-01) · **—** = N/A o solo cliente TS

| # | Escenario upstream | Cobertura Rust | Notas |
| --- | --- | --- | --- |
| 1 | Register SSO provider | ≈ | `registration/basics.rs`, `registration/discovery.rs` |
| 2 | Invalid issuer | **NEW** | `register_rejects_invalid_issuer` |
| 3 | Duplicate `providerId` | **NEW** | `register_rejects_duplicate_provider_id` |
| 4 | Sign-in email matching | **NEW** | `sign_in_sso_resolves_stored_provider_by_email_domain` |
| 5 | Sign-in domain | ≈ | `sign_in/defaults_discovery.rs`, domain en registro |
| 6 | Sign-in `providerId` | ≈ | `sign_in/oidc_basic.rs`, `oidc_callback/errors.rs` |
| 7 | Hydrate missing `authorizationEndpoint` | **NEW** + ≈ | `sign_in_sso_hydrates_missing_authorization_endpoint_at_runtime`; default SSO en `oidc_callback/discovery.rs` |
| 8 | Email lowercase OIDC | ≈ | `oidc_callback/id_token_linking.rs` |
| 9 | Sign-up disabled | ≈ | `oidc_callback/mapping_signup.rs` |
| 10 | Sign-up explicit when disabled | ≈ | idem |
| 11 | `provisionUser` on login | ≈ | `oidc_callback/provisioning.rs` |
| 12 | Sign-in org slug | ≈ | `sign_in/oidc_basic.rs` `sign_in_sso_uses_provider_for_organization_slug` |
| 13 | `provisionUser` only first sign-in | ≈ | `provisioning.rs` |
| 14 | `provisionUser` every sign-in | ≈ | `provisioning.rs` |
| 15 | Shared `redirectURI` on register | ≈ | `registration/basics.rs` `register_returns_shared_oidc_redirect_uri_when_configured` |
| 16 | Shared redirect in authorize URL | **NEW** | `sign_in_sso_uses_shared_redirect_uri_in_authorization_request` |
| 17 | Full flow shared callback | **NEW** | `oidc_callback_completes_flow_via_shared_callback_endpoint` (code `self-issued-id-token-code` cuando issuer = mock) |
| 18 | `defaultSSO` by `providerId` | ≈ | `sign_in/defaults_discovery.rs`, `oidc_callback/discovery.rs` |
| 19 | `defaultSSO` by email domain | ≈ | `sign_in_sso_uses_default_sso_oidc_by_email_domain` |
| 20 | `defaultSSO` explicit endpoints | ≈ | defaults + discovery tests |
| 21 | UserInfo-only (no `id_token`) | ≈ | `oidc_callback/id_token_linking.rs` (fixtures userinfo) |

**Nota:** el archivo upstream repite un `it("should register a new SSO provider")` en otro `describe`; el conteo **22** incluye ambos bloques describe, pero escenarios únicos son los de la tabla.

## Relación con `openauth-oidc`

| Suite | Dónde |
| --- | --- |
| `oidc/discovery.test.ts` (71) | [`openauth-oidc/05-tests.md`](../openauth-oidc/05-tests.md) |
| Redirect URI path/absolute | `openauth-oidc/tests/flow.rs` + `openauth-sso/tests/sso/oidc.rs` |

## Fuera de alcance (sin valor añadir ahora)

| Tema | Motivo para parar |
| --- | --- |
| `ssoClient()` tipado | Cliente TS; OpenAuth es server-only |
| Duplicar cada `it` de `discovery.test.ts` 1:1 en Rust | ~11 escenarios son N/A, duplicados vía SSO, o ya cubiertos en combinación — ver resumen en [openauth-oidc/05-tests.md](../openauth-oidc/05-tests.md) |
| Eliminar duplicado `oidc.rs` ↔ `flow.rs` | Mantenimiento menor; mismo comportamiento |
| SAML en este directorio | Pertenece a futura `docs/parity/openauth-saml/` |
