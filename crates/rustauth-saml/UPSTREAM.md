# rustauth-saml upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` (`reference/upstream-better-auth/VERSION.md`) |
| Upstream package/path | `@better-auth/sso`, `reference/upstream-src/1.6.9/repository/packages/sso/` |
| Rust crate | `rustauth-saml` |
| Parity level | High low-level SAML SP helper parity; ⚠️ production hardening depends on `saml-signed` and route-layer coverage |
| Scope | Server-only SAML primitives; plugin routes, provider storage, schema, and hooks live in `rustauth-sso` |

`rustauth-saml` implements the server-side SAML helper layer that Better Auth
keeps under `packages/sso/src/saml/`, `samlify.ts`, and SAML-specific route
helpers. It is not the full SSO plugin: provider CRUD, registration, cookies,
sessions, schema contributions, domain verification, and SAML HTTP endpoints are
handled by `rustauth-sso`.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| SAML config types | ✅ | `SamlProviderConfig`, IdP/SP metadata, mapping, signing/encryption keys, algorithms |
| AuthnRequest Redirect | ✅ | Builds Redirect requests and custom IDs; signed requests require key material |
| SP metadata | ✅ | Generates SP metadata with ACS and optional SLO endpoints or returns supplied XML |
| IdP metadata lookup | ✅ | Extracts first SSO/SLO service locations from metadata XML |
| ACS response parsing | ✅ | Unsigned local parser plus signed/encrypted `opensaml` flow behind `saml-signed` |
| Single assertion / XSW checks | ✅ | Enforces exactly one direct `Assertion` or `EncryptedAssertion` child |
| Timestamp validation | ✅ | `NotBefore`/`NotOnOrAfter`, 5-minute default clock skew, optional required timestamps |
| Algorithm validation | ✅ | Signature, digest, key encryption, and data encryption allow-lists and deprecated policy |
| XML hardening | ✅ | Rejects malformed XML/DOCTYPE and preserves namespace-local matching |
| Signature verification | ✅ | Real XMLDSig verification with `saml-signed`; default build fails closed |
| Encrypted assertions | ✅ | ACS decryption and standalone `decrypt_encrypted_assertion_response` use `opensaml` behind `saml-signed`; default build fails closed |
| Logout helpers | ✅ | Builds/parses Redirect and POST LogoutRequest/LogoutResponse; route semantics live in `rustauth-sso` |
| State key prefixes | ✅ | Mirrors upstream verification prefixes for AuthnRequest, assertion replay, sessions, logout |
| RelayState cookie state | ➖ | Server route concern mapped to `rustauth-sso`, not this helper crate |
| Provider registration/update schemas | ➖ | SAML config validation is split between `rustauth-sso` route code and this crate's algorithm/config types |
| Provider schema/storage | ➖ | `ssoProvider.samlConfig`, field overrides, and `domainVerified` are `rustauth-sso` plugin concerns |
| Domain verification | ➖ | Server route gate for SAML sign-in, implemented in `rustauth-sso` |
| Organization linking/provisioning | ➖ | SAML login emits a normalized profile, then `rustauth-sso` assigns org membership |
| Plugin hooks/init | ➖ | Origin bypass, sign-out SAML cleanup, and domain org assignment hooks are `rustauth-sso` concerns |
| SAML HTTP routes | ➖ | `/sign-in/sso`, ACS, metadata, SLO, logout, registration/provider routes are `rustauth-sso` scope |

## Test Coverage

| Surface | RustAuth tests | Upstream tests | Notes + verify command |
| --- | ---: | ---: | --- |
| Low-level SAML helpers | 35 direct `#[test]` cases in `crates/rustauth-saml` | 55 tests in `src/saml/assertions.test.ts` and `src/saml/algorithms.test.ts` | Run `cargo nextest run -p rustauth-saml` |
| SAML HTTP/plugin behavior | Covered in `rustauth-sso` SAML endpoint tests | 108 tests in `src/saml.test.ts` | Verify route layer with `cargo nextest run -p rustauth-sso --features saml --test sso` |
| Signed/encrypted paths | Direct in-crate signature/decryption tests plus broader fixture coverage in `rustauth-sso` | Covered through upstream `samlify` integration tests | Run `cargo nextest run -p rustauth-saml --features saml-signed` before changing crypto |
| SLO behavior | Mostly route-level tests in `rustauth-sso` | Included in upstream `src/saml.test.ts` | This crate only owns SAML message helpers |
| Registration/provider/domain/linking routes | Covered in `rustauth-sso` endpoint tests | Mixed coverage in `src/providers.test.ts`, `src/domain-verification.test.ts`, and `src/linking/org-assignment.test.ts` | Server-only boundary handled by `rustauth-sso` |

## Intentional Differences

| Topic | Better Auth | RustAuth | Why |
| --- | --- | --- | --- |
| Crypto backend | Node `samlify` and XML packages | Rust `opensaml` behind `saml-signed` | Keep crypto in Rust and share samlify-compatible behavior |
| Default unsigned handling | Allows unsigned assertions unless configured | `want_assertions_signed` defaults to `true` | Safer auth-boundary default |
| Missing crypto feature | Runtime JS stack is always present | Default build rejects signed/encrypted messages | Fail closed when verification/decryption is unavailable |
| Secrets | Plain JS strings in config | Redacted `SecretString` fields | Avoid accidental key/passphrase disclosure |
| ACS vs redirect URL | `callbackUrl` doubles as ACS and post-login redirect | `acs_url` can separate ACS from app redirect | Avoid redirect-loop and IdP-initiated ambiguity |
| Error model | `APIError` and thrown JS errors | Explicit Rust errors with stable codes | Preserve HTTP mapping while making failure modes typed |

## Open Gaps / Risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| SAML-1 | Live IdP coverage | Low | Smoke testing is manual; CI relies on fixtures and `rustauth-sso` route tests |
| SAML-2 | Deprecated algorithm default | Medium | Warn-by-default matches upstream; production should set reject or explicit allow-lists |
| SAML-3 | Crypto feature boundary | Medium | Signed/encrypted helpers require `saml-signed`; default builds intentionally fail closed |

Closed/stale audit items: signed/encrypted fixture depth is covered by
`rustauth-sso` Okta/Azure/Google, wrong-cert, tamper, XSW, and encrypted ACS
tests; standalone decryption now uses `opensaml`; direct in-crate signature
tests cover `verify_signed_saml_response`; RelayState, SLO storage/session
cleanup, and organization provisioning are route/plugin concerns implemented in
`rustauth-sso`.

## Hardening Notes

- Keep signed/encrypted SAML fail-closed unless `saml-signed` is enabled and key material is present.
- Prefer explicit reject/allow-list algorithm policies for production SAML providers.
- Treat SLO as a distributed state workflow: verification storage must be shared across instances.
- Keep RelayState, provider registration limits, domain verification, trusted-origin redirects, and cookies in the `rustauth-sso` route layer.
- Keep organization provisioning idempotent, especially when `provisionUserOnEveryLogin` or domain-based assignment is enabled.
- Validate IdP metadata size and configured entry points before persisting SAML providers.
- Prefer OIDC for new enterprise SSO integrations when the IdP supports it.

## Upstream Lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Inspect server entrypoints in `reference/upstream-src/1.6.9/repository/packages/sso/src/index.ts`.
3. Map SAML helpers from `packages/sso/src/saml/`, `samlify.ts`, and `packages/sso/src/routes/helpers.ts`.
4. Map ACS, replay, timestamp, algorithm, RelayState, schema, registration, provider, domain, linking, hooks, and SLO behavior from `packages/sso/src/routes/`, `linking/`, `saml-state.ts`, `types.ts`, `utils.ts`, and `constants.ts`.
5. Compare upstream tests in `src/saml/assertions.test.ts`, `src/saml/algorithms.test.ts`, `src/saml.test.ts`, `src/providers.test.ts`, `src/domain-verification.test.ts`, and `src/linking/org-assignment.test.ts`.
6. Verify this crate with `cargo nextest run -p rustauth-saml`.

| Upstream source | Rust target | Notes |
| --- | --- | --- |
| `src/saml/assertions.ts` | `src/saml/assertions.rs` | Assertion count, base64 whitespace, XSW rejection |
| `src/saml/algorithms.ts` | `src/saml/security.rs` | Algorithm enums, allow-lists, deprecated behavior |
| `src/saml/timestamp.ts` | `src/saml/security.rs` | Timestamp windows and required timestamp option |
| `src/saml/parser.ts` | `src/saml/xml.rs`, `src/saml/assertions.rs` | Namespace-local XML traversal and node counting |
| `src/saml/error-codes.ts` | `src/saml/logout.rs`, `rustauth-sso/src/errors.rs` | SLO error code mapping |
| `src/samlify.ts` | `src/bridge.rs`, `src/saml/signature.rs` | Runtime binding to the SAML backend |
| `src/routes/helpers.ts` | `src/bridge.rs`, `src/saml/authn_request.rs`, `src/saml/metadata.rs` | SP/IdP construction, AuthnRequest, metadata |
| `src/routes/saml-pipeline.ts` | `src/saml/assertions.rs` plus `rustauth-sso` routes | ACS parsing here; sessions/replay/users in `rustauth-sso` |
| `src/routes/sso.ts` | `src/saml/logout.rs` plus `rustauth-sso` routes | Logout XML helpers here; HTTP behavior in `rustauth-sso` |
| `src/routes/schemas.ts` | `rustauth-sso/src/routes/saml_config.rs`, `rustauth-saml/src/options.rs` | Server-side update/registration validation |
| `src/routes/providers.ts` | `rustauth-sso/src/routes/providers.rs`, `rustauth-sso/src/utils.rs` | Provider CRUD, sanitized SAML config, certificate metadata |
| `src/routes/domain-verification.ts` | `rustauth-sso/src/routes/domain_verification.rs` | Domain token and DNS verification gate |
| `src/linking/org-assignment.ts`, `src/linking/types.ts` | `rustauth-sso/src/linking.rs`, `rustauth-sso/src/hooks.rs` | Organization assignment and normalized SAML profile side effects |
| `src/saml-state.ts` | `rustauth-sso/src/state.rs`, `rustauth-sso/src/routes/saml_acs.rs` | RelayState and state validation |
| `src/types.ts` | `src/options.rs`, `rustauth-sso/src/options.rs` | SAML config, plugin SAML options, session/request records |
| `src/constants.ts` | `src/saml/state.rs` | Verification key prefixes |
| `src/index.ts` schema/hooks/init | `rustauth-sso/src/schema.rs`, `rustauth-sso/src/hooks.rs`, `rustauth-sso/src/routes/mod.rs` | Plugin server wiring and origin exceptions |
| `src/saml.test.ts` | `crates/rustauth-sso/tests/sso/endpoints/saml/` | Route-level parity and HTTP redirects |

## Links

- [README](./README.md)
- [Workspace parity index](../../docs/parity/README.md)
