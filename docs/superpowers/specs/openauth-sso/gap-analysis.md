# OpenAuth SSO Upstream Gap Analysis

This file tracks the remaining differences between the current
`crates/openauth-sso` implementation and the upstream server-side Better Auth
SSO package at `upstream/better-auth/1.6.9/repository/packages/sso`.

The goal is parity of behavior where it makes sense for OpenAuth. It is not a
line-by-line port.

## Sources Compared

- Upstream:
  - `src/routes/sso.ts`
  - `src/routes/providers.ts`
  - `src/routes/domain-verification.ts`
  - `src/routes/saml-pipeline.ts`
  - `src/routes/helpers.ts`
  - `src/routes/schemas.ts`
  - `src/oidc/discovery.ts`
  - `src/saml/assertions.ts`
  - `src/saml/algorithms.ts`
  - `src/saml/timestamp.ts`
  - `src/linking/org-assignment.ts`
  - Upstream tests under `src/**/*.test.ts`
- OpenAuth:
  - `crates/openauth-sso/src/options.rs`
  - `crates/openauth-sso/src/routes/mod.rs`
  - `crates/openauth-sso/src/oidc/discovery.rs`
  - `crates/openauth-sso/src/saml/*`
  - `crates/openauth-sso/src/linking.rs`
  - `crates/openauth-sso/src/store.rs`
  - `crates/openauth-sso/tests/sso/*`

## Status Summary

| Area | Status | Notes |
| --- | --- | --- |
| Plugin/schema | Mostly complete | Physical DB table/fields follow OpenAuth naming rules. Field mapping option from upstream is intentionally not exposed for now. |
| Provider CRUD | Mostly complete | User-owned paths, organization admin/owner access, and registration membership validation work. |
| Provider sanitization | Mostly complete | OIDC secrets hidden, client IDs masked with upstream semantics, SAML cert metadata returned, and responses include both `providerType` and upstream-compatible `type`. |
| Registration | Mostly complete | OIDC/SAML basics, org membership validation, dynamic providersLimit, OIDC `redirectURI`, SAML IdP metadata entry-point normalization, metadata size validation, initial domain token return work, and typed provisioning callbacks. |
| OIDC discovery | Mostly complete | Registration-time and runtime discovery work with stable error codes, aggregate missing-field reporting, user-supplied endpoint preservation, and trusted-origin validation. Missing some upstream option callbacks. |
| OIDC sign-in/callback | Mostly complete | Authorization URL, token exchange, UserInfo, ID-token-only fallback, ID token validation, session creation, defaultSSO, organizationSlug, newUser redirect, organization assignment, provisioning callback, and strict trust semantics work. |
| Domain verification | Mostly complete | Register-time token return, token request/reuse, DNS TXT verify, DNS failure taxonomy, secondary storage, org access checks, multi-domain first-host behavior, custom token prefixes, URL/bare domains, and already-verified conflicts work. |
| SAML metadata | Mostly complete | Generated and passthrough SP metadata work, including SLO bindings, NameID format, signed-request metadata flags, and explicit `format=json` rejection. |
| SAML sign-in | Partial | Unsigned Redirect AuthnRequest works and register-time IdP metadata can supply the entry point. Signed AuthnRequest is missing. |
| SAML ACS | Partial | Unsigned and signed assertion flows work, IdP metadata `entityID` is honored for issuer validation, GET callback browser redirects work, IdP POSTs can bypass origin security per endpoint, structural errors redirect to safe error callbacks when available, replay/missing assertion ID edges fail closed, encrypted assertions fail closed with an explicit unsupported code, and assertion counting uses parser-backed local-name traversal. Missing encrypted assertion decryption and broader ACS edge-case coverage. |
| SAML signature validation | Mostly complete for current scope | ACS/SLO signed XML and Redirect SLO are covered behind `saml-signed`. AuthnRequest signing is not implemented. |
| SLO | Mostly complete | Local logout, core sign-out state cleanup hook, SP-initiated Redirect/POST binding, configured IdP SingleLogoutService selection, metadata XML SLO extraction, LogoutRequest/LogoutResponse handling, IdP POST origin bypass, POST form generation, and negative state tests work. |
| Organization assignment | Mostly complete | SSO provider organization assignment and verified-domain assignment work for SSO flows. Non-SSO auth hook integration remains blocked on core hook surface. |
| OpenAPI | Mostly complete | SSO operation IDs, request body schemas, path parameters, domain-verification endpoints, and hidden IdP POST callback routes are covered. Response schemas can still be expanded. |
| Modularization | Mostly complete | Route implementation is split by endpoint family; `routes/mod.rs` is now a thin endpoint aggregator plus shared SAML validation helpers. |

## High-Risk Behavioral Gaps

### Trust Semantics

Implemented: SSO now requires an explicit SSO trust signal before implicit
account linking. Provider-asserted `email_verified=true` is only trusted when
`trustEmailVerified` is enabled, or when the provider has a verified domain that
matches the user email domain. Core OAuth keeps its existing social-provider
default through a per-call linking flag.

### Redirect Safety

Implemented for the current SSO state paths: SSO validates callback URLs, error
URLs, new-user URLs, ACS fallback targets, SAML logout callback URLs, and SLO
RelayState redirects. It rejects untrusted absolute URLs, protocol-relative
URLs, and loops back to SSO callback/ACS endpoints.

### Runtime Discovery

Implemented: OpenAuth hydrates incomplete OIDC config during registration,
sign-in, and callback. Discovery failures now map to stable JSON or redirect
codes, and discovery plus discovered endpoint origins must be trusted by
OpenAuth's trusted-origin policy.

### Organization Access

Implemented for provider CRUD: user-owned providers still require ownership,
organization-linked providers require an `owner` or `admin` membership when the
organization plugin is installed, and regular members are rejected. Registration
with `organizationId` requires membership. Domain verification allows direct
provider owners or organization members and rejects unrelated users.

## Detailed Gaps

### Provider Endpoints

Implemented:

- List includes user-owned providers plus org providers where the user is admin
  or owner.
- Get/update/delete use the same access policy.
- Role parsing accepts comma-separated roles.

- Short and long OIDC client IDs are masked with upstream-compatible
  `****`/`****last4` semantics.
- SAML sanitization returns sanitized `certificateError` metadata for malformed
  certificates while keeping raw cert material out of API responses.

### Registration

Implemented:

- `organizationId` requires membership validation when the organization plugin
  is installed.

Upstream behavior implemented since the initial gap pass:

- `providersLimit` can be a callback.
- Domain verification enabled returns and stores a generated token from
  register.
- SAML config models upstream IdP/SP metadata, key, encryption, and additional
  params fields.
- IdP metadata XML size is validated during register/update.
- IdP entry point can come from metadata XML or `singleSignOnService`.

Upstream behavior still missing or partial:

- Registration response includes `redirectURI` for OIDC compatibility.

### OIDC

Upstream behavior still missing or partial:

- `defaultSSO` provider selection is implemented for `/sign-in/sso` and both
  OIDC callback routes before DB lookup.
- `organizationSlug` lookup is implemented for stored organization-linked
  providers.
- Runtime discovery is implemented for incomplete `defaultSSO` and stored OIDC
  configs during sign-in and callback.
- Discovery errors are mapped to stable API/redirect codes for registration,
  runtime sign-in, and OIDC callback paths.
- Discovery trusted-origin validation is implemented for the discovery URL and
  discovered authorization, token, JWKS, and UserInfo endpoints.
- Discovery reports all missing required fields as `discovery_incomplete` and
  preserves explicit user-supplied endpoint overrides over discovered values.
- Callback can use validated ID token claims when UserInfo is absent.
- `newUserCallbackURL` redirect selection is implemented for OIDC callbacks.
- `provisionUser` callbacks are modeled and called after SSO session creation.
- `extraFields` mappings are parsed in options but not carried into a raw
  profile shape.

### SAML

Upstream behavior implemented since the initial gap pass:

- `SamlConfig.idpMetadata`, SP private keys, encryption keys, private key
  passphrases, and `additionalParams` are modeled.

Upstream behavior still missing or partial:

- AuthnRequests cannot be signed yet.
- Generated SP metadata includes SLO Redirect/POST services when enabled,
  signature flags, and NameID format.
- SP metadata passthrough is implemented when `spMetadata.metadata` is supplied.
- `format=json` query is explicitly rejected.
- Encrypted assertion decryption is not implemented.
- Exactly one encrypted assertion fails closed with
  `ENCRYPTED_SAML_ASSERTION_UNSUPPORTED` before provisioning.
- Assertion counting now uses parser-backed local-name traversal and covers
  namespace prefixes, encrypted assertion counts, nested XSW patterns, invalid
  XML, and `AssertionConsumerService` false positives.
- Runtime algorithm validation from parsed response XML is incomplete.

### SLO

Implemented:

- Normal OpenAuth `/sign-out` captures the current session before core deletion
  and removes only that session's SAML lookup records afterward.

### Domain Verification

Upstream behavior still missing or partial:

- Secondary storage backend is implemented through `SsoStateStore` for domain
  verification and shared SSO state paths.
- Org provider access policy is implemented for direct provider owners and
  organization members.
- Custom token prefix, bare domain, URL domain, and already verified conflicts
  are covered.

## Recommended Execution Order

1. Split `routes/mod.rs` enough to keep future changes reviewable.
2. Implement provider org access policy and registration membership validation.
3. Expand SAML metadata/config shape.
4. Add AuthnRequest signing.
5. Add SLO sign-out hook cleanup.
7. Expand OpenAPI response metadata.
8. Fill remaining upstream tests by area until the checklist has no broad
    uncovered categories.
