# 05 — Tests y cobertura

Recontado desde archivos (no desde README), 2026-06-01.

## Conteos

| Suite | Archivo | Tests |
| --- | --- | --- |
| Upstream discovery | `packages/sso/src/oidc/discovery.test.ts` | **71** `it(` |
| Upstream SSO OIDC E2E | `packages/sso/src/oidc.test.ts` | **22** `it(` |
| `openauth-oidc` unit+async | `src/discovery.rs` (`mod tests`) | **23** |
| `openauth-oidc` integration | `tests/flow.rs` | **3** |
| **Total crate** | | **26** |
| SSO E2E paridad upstream | `openauth-sso/tests/sso/endpoints/oidc_upstream_parity.rs` | **6** (2026-06-01) |
| SSO registration discovery | `openauth-sso/tests/sso/endpoints/registration/discovery.rs` | **6** |
| SSO callback discovery | `openauth-sso/tests/sso/endpoints/oidc_callback/discovery.rs` | **8** |
| SSO redirect helpers | `openauth-sso/tests/sso/oidc.rs` | **3** (mismos casos que `flow.rs`) |

```bash
grep -c '^\s*it(' reference/upstream-src/1.6.9/repository/packages/sso/src/oidc/discovery.test.ts
grep -cE '#\[test\]|#\[tokio::test\]' crates/openauth-oidc/src/discovery.rs crates/openauth-oidc/tests/flow.rs
```

## Matriz completa: `discovery.test.ts` (71) → cobertura OpenAuth

Leyenda: **OIDC** = `openauth-oidc` · **SSO** = `openauth-sso` tests · **—** = no cubierto / N/A · **≈** = cubierto

| # | Test upstream (`discovery.test.ts`) | OIDC | SSO | Notas |
| --- | --- | --- | --- | --- |
| 1 | compute URL sin trailing slash | ≈ | ≈ | `discovery_url_trims_trailing_slash` |
| 2 | compute URL con trailing slash | ≈ | ≈ | idem |
| 3 | compute URL con path en issuer | ≈ | — | `discovery_url_preserves_issuer_path` |
| 4 | compute URL path + trailing slash | ≈ | — | idem |
| 5 | validateDiscoveryUrl HTTPS | ≈ | — | `normalize_absolute_http_url_accepts_http_and_https` |
| 6 | validateDiscoveryUrl HTTP | ≈ | — | idem |
| 7 | validateDiscoveryUrl invalid URL | — | SSO | `register_rejects_invalid_*` / validation |
| 8 | validateDiscoveryUrl non-HTTP | ≈ | — | `absolute_http_url_api_*` / ftp |
| 9 | invalid URL → code | ≈ | — | `discovery_errors_expose_stable_codes` |
| 10 | non-HTTP → code | ≈ | — | idem |
| 11 | untrusted discovery URL | ≈ | SSO | async + `register_rejects_untrusted_oidc_discovery_origin` |
| 12 | valid discovery document | ≈ | — | minimal metadata test |
| 13 | only required fields | ≈ | — | idem |
| 14–17 | missing field (each required) | ≈ | — | per-field + all missing |
| 18 | list all missing fields | ≈ | — | `discovery_validation_reports_all_missing` |
| 19 | issuer_mismatch | — | SSO | registration/callback discovery errors |
| 20 | issuer trailing slash (discovered) | ≈ | — | `discovery_validation_normalizes_issuer_trailing_slash` |
| 21 | issuer trailing slash (configured) | ≈ | — | idem |
| 22 | token auth: existing wins | ≈ | — | override test parcial |
| 23 | prefer client_secret_basic | ≈ | — | `token_endpoint_authentication_prefers_client_secret_basic_when_both_supported` |
| 24 | client_secret_post only | ≈ | SSO | unit + `oidc_callback_uses_client_secret_post_token_auth` |
| 25 | unsupported methods → basic | ≈ | — | `token_endpoint_authentication_defaults_*` |
| 26 | tls_client_auth only → basic | ≈ | — | idem |
| 27 | not specified → basic | ≈ | — | idem |
| 28 | empty array → basic | ≈ | — | idem |
| 29 | normalize: absolute unchanged | ≈ | — | relative endpoints test |
| 30 | normalize required relative | ≈ | — | idem |
| 31 | normalize all optional relative | ≈ | — | revocation/end_session/introspect |
| 32 | normalize invalid URL | ≈ | — | `endpoint_url_api_*` |
| 33 | normalize untrusted | ≈ | — | untrusted optional/required async |
| 34 | normalizeUrl absolute unchanged | ≈ | — | |
| 35 | normalizeUrl to absolute | ≈ | — | |
| 36 | normalizeUrl invalid | ≈ | — | |
| 37 | normalizeUrl bad protocol | ≈ | — | ftp |
| 38 | needsRuntime undefined | — | — | **N/A** (`&OidcConfig` en Rust) |
| 39 | needsRuntime empty | ≈ | — | runtime requirements test |
| 40 | needsRuntime missing token | ≈ | — | idem |
| 41 | needsRuntime missing jwks | ≈ | — | idem |
| 42 | needsRuntime satisfied | ≈ | — | idem |
| 43 | needsRuntime missing authz | ≈ | — | idem |
| 44 | fetch valid | ≈ | — | vía discover async mocks |
| 45 | fetch 404 | ≈ | — | `fetch_discovery_document_classifies_*` |
| 46 | fetch AbortError timeout | — | — | reqwest `is_timeout()`; no AbortError name |
| 47 | fetch 408 | ≈ | — | clasificado como Timeout |
| 48 | fetch 500 | ≈ | — | unexpected_error |
| 49 | fetch empty body | ≈ | — | invalid_json |
| 50 | fetch bad JSON | ≈ | — | invalid_json |
| 51 | fetch unknown error | — | — | parcial vía Request |
| 52 | discover hydrated valid | ≈ | SSO | `register_discovers_oidc_endpoints_*` |
| 53 | merge existing precedence | ≈ | — | `discovery_preserves_user_supplied_*` |
| 54 | custom discovery endpoint | — | SSO | implícito en mock server |
| 55 | discovery URL from existing | — | — | parcial |
| 56 | discover issuer mismatch | — | SSO | stable error codes |
| 57 | discover missing fields | ≈ | — | unit validation |
| 58 | discover 404 | ≈ | SSO | registration discovery errors |
| 59 | include scopes_supported in hydrated | ≈ | — | struct sí; **no** a `scopes` (test runtime) |
| 60 | discover minimal optional | ≈ | — | |
| 61 | keep existing fill missing | — | SSO | skip_discovery partial + runtime |
| 62 | discover default basic unsupported | ≈ | — | |
| 63 | partial existing fill | — | SSO | runtime discovery tests |
| 64 | extra unknown fields | — | — | serde ignora |
| 65 | untrusted main discovery URL | ≈ | SSO | `register_rejects_untrusted_*` |
| 66 | untrusted discovered URLs | ≈ | — | async untrusted token/revocation |
| 67 | ensureRuntime unchanged | ≈ | — | runtime test parcial |
| 68 | ensureRuntime hydrates | ≈ | SSO | callback/sign-in discovery |
| 69 | ensureRuntime preserves fields | ≈ | — | scopes test |
| 70 | ensureRuntime throws | — | SSO | discovery error redirect |
| 71 | ensureRuntime untrusted | — | SSO | untrusted origin registration |

**Resumen matriz:** ~45/71 con cobertura directa o fuerte en `openauth-oidc`; ~+15 vía SSO; ~11 sin test dedicado (varios son N/A o comportamiento documentado en [07-deep-audit.md](./07-deep-audit.md)).

## Tests en `openauth-oidc` (inventario)

### `src/discovery.rs`

| Test | Cubre upstream # aprox. |
| --- | --- |
| `normalizes_relative_discovery_endpoints_against_issuer_path` | 29–31 |
| `discovery_url_preserves_issuer_path` | 3–4 |
| `absolute_http_url_api_rejects_relative_and_non_http_values` | 8, 10 |
| `endpoint_url_api_resolves_relative_values_against_issuer_path` | 32, 37 |
| `runtime_discovery_requirements_match_sign_in_and_callback_needs` | 38–43 |
| `discovery_errors_expose_stable_codes_and_statuses` | 9–10, HTTP status |
| `discovery_validation_reports_all_missing_required_fields` | 18 |
| `discovery_validation_reports_each_missing_required_field` | 14–17 |
| `token_endpoint_authentication_defaults_for_empty_or_unsupported_methods` | 25–28 |
| `discovery_validation_accepts_document_without_optional_metadata` | 12–13 |
| `fetch_discovery_document_classifies_http_and_json_errors` | 44–50 |
| `discovery_rejects_untrusted_discovered_endpoint_origins` | 66 |
| `discovery_rejects_untrusted_optional_endpoint_origins` | 33, 66 |
| `discovery_preserves_user_supplied_endpoints_over_discovered_values` | 53 |
| `runtime_discovery_preserves_only_explicit_request_scopes` | 59, 69 |
| `discovery_validation_normalizes_issuer_trailing_slash` | 20–21 |
| `discovery_validation_rejects_issuer_mismatch` | 19 |
| `token_endpoint_authentication_prefers_client_secret_basic_when_both_supported` | 23 |
| `token_endpoint_authentication_selects_client_secret_post_when_only_supported` | 24 |
| `normalize_absolute_http_url_accepts_http_and_https` | 5–6 |

### `tests/flow.rs`

| Test | Cubre |
| --- | --- |
| `discovery_url_trims_trailing_slash` | 1–2 |
| `shared_redirect_uri_accepts_path_or_absolute_url` | redirect (sso.ts) |
| `normalize_url_rejects_relative_values` | 36 |

## E2E: `oidc.test.ts` (22) — solo `openauth-sso`

No son responsabilidad del crate `openauth-oidc`. Matriz completa y auditoría en [openauth-sso/06-tests.md](../openauth-sso/06-tests.md). Resumen de frontera en [06-boundary-sso.md](./06-boundary-sso.md).

Tests SSO que ejercitan discovery/endpoints persistidos (muestra):

| Test SSO | Qué valida |
| --- | --- |
| `register_discovers_oidc_endpoints_when_skip_discovery_is_false` | discovery + **revocation/end_session/introspection** en DB (superset vs upstream register) |
| `register_allows_skip_discovery_partial_config_for_runtime_discovery` | skip + runtime |
| `register_returns_stable_oidc_discovery_error_code` | códigos error |
| `register_rejects_untrusted_oidc_discovery_origin` | SSRF/trust |
| `register_accepts_strict_manual_oidc_matrix_for_common_idps` | `strict_manual_endpoint_origins` |
| `oidc_callback_redirects_stable_discovery_error_code` | runtime callback |
| `sign_in_sso_returns_stable_discovery_error_code` | runtime sign-in |

## Verificación

```bash
cargo nextest run -p openauth-oidc
cargo nextest run -p openauth-sso --test sso -- discovery
```
