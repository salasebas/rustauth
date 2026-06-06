# openauth-saml upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` (`reference/upstream-better-auth/VERSION.md`) |
| Upstream package/path | `@better-auth/sso`, `reference/upstream-src/1.6.9/repository/packages/sso/` |
| Rust crate | `openauth-saml` |
| Parity level | ⚠️ Partial low-level SAML SP helper parity |
| Scope | Server-only SAML primitives; plugin routes, provider storage, schema, and hooks live in `openauth-sso` |

`openauth-saml` implements the server-side SAML helper layer that Better Auth
keeps under `packages/sso/src/saml/`, `samlify.ts`, and SAML-specific route
helpers. It is not the full SSO plugin: provider CRUD, registration, cookies,
sessions, schema contributions, domain verification, and SAML HTTP endpoints are
handled by `openauth-sso`.

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| SAML config types | ✅ | `SamlProviderConfig`, IdP/SP metadata, mapping, signing/encryption keys, algorithms |
| AuthnRequest Redirect | ✅ | Builds Redirect requests and custom IDs; signed requests require key material |
| SP metadata | ✅ | Generates SP metadata with ACS and optional SLO endpoints or returns supplied XML |
| IdP metadata lookup | ✅ | Extracts first SSO/SLO service locations from metadata XML |
| ACS response parsing | ⚠️ | Unsigned local parser plus signed/encrypted `opensaml` flow behind `saml-signed` |
| Single assertion / XSW checks | ✅ | Enforces exactly one direct `Assertion` or `EncryptedAssertion` child |
| Timestamp validation | ✅ | `NotBefore`/`NotOnOrAfter`, 5-minute default clock skew, optional required timestamps |
| Algorithm validation | ✅ | Signature, digest, key encryption, and data encryption allow-lists and deprecated policy |
| XML hardening | ✅ | Rejects malformed XML/DOCTYPE and preserves namespace-local matching |
| Signature verification | ⚠️ | Real XMLDSig verification only with `saml-signed`; default build fails closed |
| Encrypted assertions | ⚠️ | Real ACS decryption flows through `opensaml`; standalone helper is a stub |
| Logout helpers | ⚠️ | Builds/parses Redirect and POST LogoutRequest/LogoutResponse; route semantics live in `openauth-sso` |
| State key prefixes | ✅ | Mirrors upstream verification prefixes for AuthnRequest, assertion replay, sessions, logout |
| RelayState cookie state | ➖ | Server route concern mapped to `openauth-sso`, not this helper crate |
| Provider registration/update schemas | ➖ | SAML config validation is split between `openauth-sso` route code and this crate's algorithm/config types |
| Provider schema/storage | ➖ | `ssoProvider.samlConfig`, field overrides, and `domainVerified` are `openauth-sso` plugin concerns |
| Domain verification | ➖ | Server route gate for SAML sign-in, implemented in `openauth-sso` |
| Organization linking/provisioning | ➖ | SAML login emits a normalized profile, then `openauth-sso` assigns org membership |
| Plugin hooks/init | ➖ | Origin bypass, sign-out SAML cleanup, and domain org assignment hooks are `openauth-sso` concerns |
| SAML HTTP routes | ➖ | `/sign-in/sso`, ACS, metadata, SLO, logout, registration/provider routes are `openauth-sso` scope |

## Test Coverage

| Surface | OpenAuth tests | Upstream tests | Notes + verify command |
| --- | ---: | ---: | --- |
| Low-level SAML helpers | 32 direct `#[test]` cases in `crates/openauth-saml` | 55 tests in `src/saml/assertions.test.ts` and `src/saml/algorithms.test.ts` | Run `cargo nextest run -p openauth-saml` |
| SAML HTTP/plugin behavior | Covered in `openauth-sso` SAML endpoint tests | 108 tests in `src/saml.test.ts` | Verify route layer with `cargo nextest run -p openauth-sso --features saml --test sso` |
| Signed/encrypted paths | Shallow in-crate; broader fixture coverage in `openauth-sso` | Covered through upstream `samlify` integration tests | Run `cargo nextest run -p openauth-saml --features saml-signed` before changing crypto |
| SLO behavior | Mostly route-level tests in `openauth-sso` | Included in upstream `src/saml.test.ts` | This crate only owns SAML message helpers |
| Registration/provider/domain/linking routes | Covered in `openauth-sso` endpoint tests | Mixed coverage in `src/providers.test.ts`, `src/domain-verification.test.ts`, and `src/linking/org-assignment.test.ts` | Server-only boundary handled by `openauth-sso` |

## Intentional Differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| Crypto backend | Node `samlify` and XML packages | Rust `opensaml` behind `saml-signed` | Keep crypto in Rust and share samlify-compatible behavior |
| Default unsigned handling | Allows unsigned assertions unless configured | `want_assertions_signed` defaults to `true` | Safer auth-boundary default |
| Missing crypto feature | Runtime JS stack is always present | Default build rejects signed/encrypted messages | Fail closed when verification/decryption is unavailable |
| Secrets | Plain JS strings in config | Redacted `SecretString` fields | Avoid accidental key/passphrase disclosure |
| ACS vs redirect URL | `callbackUrl` doubles as ACS and post-login redirect | `acs_url` can separate ACS from app redirect | Avoid redirect-loop and IdP-initiated ambiguity |
| Error model | `APIError` and thrown JS errors | Explicit Rust errors with stable codes | Preserve HTTP mapping while making failure modes typed |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| SAML-1 | Signed/encrypted fixture depth | High | Add Okta/Azure/Google-shaped signed, bad-cert, and encrypted assertions |
| SAML-2 | Standalone decryption helper stub | Medium | `decrypt_encrypted_assertion_response` returns failure; real ACS decryption uses `opensaml` |
| SAML-3 | In-crate async signature tests | Medium | `verify_signed_*` helpers lack direct async tests in this crate |
| SAML-4 | RelayState and cookie-backed state | Medium | Better Auth uses `relay_state`; OpenAuth route parity belongs in `openauth-sso` |
| SAML-5 | SLO production semantics | Medium | Storage, TTL, idempotency, session cleanup, and replay protection are route-level concerns |
| SAML-6 | Organization provisioning side effects | Medium | Requires idempotent server hooks and organization plugin behavior in `openauth-sso` |
| SAML-7 | Deprecated algorithm default | Medium | Warn-by-default matches upstream; production should set reject or explicit allow-lists |
| SAML-8 | Live IdP coverage | Low | Smoke testing is manual; CI relies on fixtures |

## Hardening Notes

- Keep signed/encrypted SAML fail-closed unless `saml-signed` is enabled and key material is present.
- Prefer explicit reject/allow-list algorithm policies for production SAML providers.
- Treat SLO as a distributed state workflow: verification storage must be shared across instances.
- Keep RelayState, provider registration limits, domain verification, trusted-origin redirects, and cookies in the `openauth-sso` route layer.
- Keep organization provisioning idempotent, especially when `provisionUserOnEveryLogin` or domain-based assignment is enabled.
- Validate IdP metadata size and configured entry points before persisting SAML providers.
- Prefer OIDC for new enterprise SSO integrations when the IdP supports it.

## Upstream Lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Inspect server entrypoints in `reference/upstream-src/1.6.9/repository/packages/sso/src/index.ts`.
3. Map SAML helpers from `packages/sso/src/saml/`, `samlify.ts`, and `packages/sso/src/routes/helpers.ts`.
4. Map ACS, replay, timestamp, algorithm, RelayState, schema, registration, provider, domain, linking, hooks, and SLO behavior from `packages/sso/src/routes/`, `linking/`, `saml-state.ts`, `types.ts`, `utils.ts`, and `constants.ts`.
5. Compare upstream tests in `src/saml/assertions.test.ts`, `src/saml/algorithms.test.ts`, `src/saml.test.ts`, `src/providers.test.ts`, `src/domain-verification.test.ts`, and `src/linking/org-assignment.test.ts`.
6. Verify this crate with `cargo nextest run -p openauth-saml`.

| Upstream source | Rust target | Notes |
| --- | --- | --- |
| `src/saml/assertions.ts` | `src/saml/assertions.rs` | Assertion count, base64 whitespace, XSW rejection |
| `src/saml/algorithms.ts` | `src/saml/security.rs` | Algorithm enums, allow-lists, deprecated behavior |
| `src/saml/timestamp.ts` | `src/saml/security.rs` | Timestamp windows and required timestamp option |
| `src/saml/parser.ts` | `src/saml/xml.rs`, `src/saml/assertions.rs` | Namespace-local XML traversal and node counting |
| `src/saml/error-codes.ts` | `src/saml/logout.rs`, `openauth-sso/src/errors.rs` | SLO error code mapping |
| `src/samlify.ts` | `src/bridge.rs`, `src/saml/signature.rs` | Runtime binding to the SAML backend |
| `src/routes/helpers.ts` | `src/bridge.rs`, `src/saml/authn_request.rs`, `src/saml/metadata.rs` | SP/IdP construction, AuthnRequest, metadata |
| `src/routes/saml-pipeline.ts` | `src/saml/assertions.rs` plus `openauth-sso` routes | ACS parsing here; sessions/replay/users in `openauth-sso` |
| `src/routes/sso.ts` | `src/saml/logout.rs` plus `openauth-sso` routes | Logout XML helpers here; HTTP behavior in `openauth-sso` |
| `src/routes/schemas.ts` | `openauth-sso/src/routes/saml_config.rs`, `openauth-saml/src/options.rs` | Server-side update/registration validation |
| `src/routes/providers.ts` | `openauth-sso/src/routes/providers.rs`, `openauth-sso/src/utils.rs` | Provider CRUD, sanitized SAML config, certificate metadata |
| `src/routes/domain-verification.ts` | `openauth-sso/src/routes/domain_verification.rs` | Domain token and DNS verification gate |
| `src/linking/org-assignment.ts`, `src/linking/types.ts` | `openauth-sso/src/linking.rs`, `openauth-sso/src/hooks.rs` | Organization assignment and normalized SAML profile side effects |
| `src/saml-state.ts` | `openauth-sso/src/state.rs`, `openauth-sso/src/routes/saml_acs.rs` | RelayState and state validation |
| `src/types.ts` | `src/options.rs`, `openauth-sso/src/options.rs` | SAML config, plugin SAML options, session/request records |
| `src/constants.ts` | `src/saml/state.rs` | Verification key prefixes |
| `src/index.ts` schema/hooks/init | `openauth-sso/src/schema.rs`, `openauth-sso/src/hooks.rs`, `openauth-sso/src/routes/mod.rs` | Plugin server wiring and origin exceptions |
| `src/saml.test.ts` | `crates/openauth-sso/tests/sso/endpoints/saml/` | Route-level parity and HTTP redirects |

## Links

- [README](./README.md)
- [Workspace parity index](../../docs/parity/README.md)
