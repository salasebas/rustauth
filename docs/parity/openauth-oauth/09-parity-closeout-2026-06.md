# 09 — `openauth-oauth` gap closeout (June 2026)

Closeout after [08-findings-pass2.md](./08-findings-pass2.md). Goal: parity on **OAuth2 client primitives** (`@better-auth/core/oauth2`) with regression tests; document architectural or low-ROI items explicitly.

## Closed in code

| Gap | Solution |
| --- | --- |
| Introspection without `aud` + required audience | `introspection_includes_audience` — validate audience only if payload has truthy `aud` |
| JWS → remote introspection fallback | `local_jws_failure_allows_remote_fallback` when `remote_verify` is set |
| `validate_token` without JWKS cache | `validate_token_with_client` → `get_cached_jwks_for_token` |
| Generic OAuth `tokenUrlParams` | `additional_params` on code exchange (not `override_params`) — `openauth-plugins` |

## Regression tests

| Test | Covers |
| --- | --- |
| `verify_access_token_rejects_remote_missing_active_and_missing_audience` | Missing `aud` OK; wrong `aud` fails |
| `validate_token_reuses_cached_jwks_for_known_kid` | Shared JWKS cache |
| `authorization_code_additional_params_cannot_replace_existing_body_fields` | `additionalParams` parity |
| `provider_token_url_params_cannot_override_protected_token_request_values` | generic-oauth plugin |

**Suite:** `cargo nextest run -p openauth-oauth` → **57** passed (June 2026).

## Not implemented (stop here)

| Topic | Reason |
| --- | --- |
| Wire `verify_access_token` into MCP/AS | `openauth-oauth-provider` uses its own validation (DB + JWT plugin); not an oauth crate gap |
| `AwaitableFunction<ProviderOptions>` | Idiomatic Rust: async providers in plugin/social layer |
| Upstream client_credentials Basic Base64URL | Documented upstream quirk; OpenAuth uses RFC 7617 |
| `get_jwks` without custom fetch | Low: use `get_jwks_with_client` + injected client |

## Verdict

**High parity** on authorization code, refresh, client credentials, PKCE, JWT/JWKS, introspection, and `verify_access_token` for server-side use. No critical functional gaps remain in this crate.
