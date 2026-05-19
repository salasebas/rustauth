# OpenAuth SSO Requirements

OpenAuth SSO ports the server-side behavior from Better Auth `packages/sso`
into the existing Rust workspace. Upstream is the product reference, not a
shape to copy mechanically.

## Core Requirements

- Expose a server-only `openauth_sso::sso(SsoOptions) -> AuthPlugin`.
- Keep public JSON fields compatible where useful, such as `providerId`,
  `oidcConfig`, `samlConfig`, `organizationId`, and `domainVerified`.
- Store SSO providers in logical model `ssoProvider` and physical table
  `sso_providers`.
- Keep physical database tables plural and fields snake_case.
- Do not expose Better Auth's custom SSO field-name mapping option yet. OpenAuth
  treats logical schema names as a stable plugin contract and physical storage
  names as adapter-owned snake_case/plural names.
- Never return OIDC client secrets or raw SAML private keys from read endpoints.
- Register provider management, registration, OIDC, SAML, SLO, and optional
  domain verification endpoints.
- Use OpenAuth verification storage or secondary storage for ephemeral state:
  OAuth state, SAML AuthnRequest IDs, assertion replay keys, SAML session lookup,
  logout requests, and domain verification tokens.
- Adapt upstream tests into focused Rust tests instead of skipping scenarios.

## Coverage Source

- `docs/superpowers/plans/2026-05-12-upstream-sso-server-checklist.md`
- `upstream/better-auth/1.6.9/repository/packages/sso`

## Current Parity Baseline

Implemented and covered:

- Plugin registration, public re-export through `openauth --features sso`, and
  `ssoProvider` schema with physical table `sso_providers`.
- Provider registration/list/get/update/delete for user-owned providers.
- OIDC registration with discovery hydration, explicit endpoint mode, client
  secret sanitization, authorization URL generation, code exchange, UserInfo
  mapping, ID token/JWKS validation, account linking, session creation, and
  shared redirect URI support.
- Domain verification endpoint registration, token request/reuse, DNS TXT
  verification, custom resolver support, public-suffix domain rejection, and
  `domainVerified` reset when domains change.
- SAML SP metadata, AuthnRequest redirect generation, RelayState/AuthnRequest
  verification storage, ACS parsing, timestamp validation, replay protection,
  unsigned flow when explicitly allowed, signed ACS validation behind
  `saml-signed`, SLO request/response parsing, and signed SLO validation.
- SAML provider sanitization without raw certificate exposure, including
  certificate fingerprint, validity, public-key metadata, and sanitized
  `certificateError` metadata when a stored certificate cannot be parsed.
- Organization-linked provider access, `organizationSlug` provider selection,
  `organizationProvisioning` options, normalized SSO profiles, and OIDC/SAML
  post-login organization assignment.
- Typed `provisionUser` and `provisionUserOnEveryLogin` callbacks after SSO
  session creation.
- Security-sensitive SSO events must be auditable through typed callbacks and
  internal logging: provider lifecycle changes, domain verification,
  SAML replay rejection, SAML signature failure, and SLO session cleanup.

## Remaining Requirements By Area

### Provider Access And Organization Integration

- Provider management must support organization-linked providers when the
  organization plugin is enabled:
  - List org providers for users with `owner` or `admin` roles.
  - Accept comma-separated roles and trim whitespace.
  - Reject regular members for get/update/delete.
  - Preserve user-owned behavior when no organization plugin is installed.
- Registration with `organizationId` must verify that the current user belongs
  to that organization before persisting the provider.
- `/sign-in/sso` must resolve `organizationSlug` to `organizationId` and select
  the matching provider.
- Domain-based organization assignment for non-SSO sign-up/sign-in flows must
  run after successful session creation, reuse the same provider-domain matching
  rules as SSO, and require verified SSO provider domains when domain
  verification is enabled.

### Options And Public API

- `providersLimit` must support a dynamic callback based on the authenticated
  user, not only a static `usize`.
- `defaultSSO` providers must participate in sign-in and callbacks before
  database providers, matching upstream behavior.
- `trustEmailVerified` must not make all provider-asserted verified emails a
  trusted account-linking signal unless explicitly enabled. Domain verification
  and configured trusted providers should remain the preferred trust boundary.

### Provider Registration

- Registration should return an initial `domainVerificationToken` when domain
  verification is enabled, matching upstream. The existing request endpoint
  already creates/reuses tokens, but register currently only initializes
  `domainVerified=false`.
- Registration and update must validate SAML IdP metadata size against
  `saml.maxMetadataSize`.
- SAML provider registration must accept the upstream IdP/SP metadata surface:
  `idpMetadata.metadata`, `entityID`, `entityURL`, `redirectURL`, `cert`,
  `singleSignOnService`, `singleLogoutService`, SP private key/passphrase,
  encryption flags/keys, `privateKey`, `decryptionPvk`, and
  `additionalParams`.
- SAML config should allow a usable IdP entry point from metadata XML or
  `idpMetadata.singleSignOnService`, not only top-level `entryPoint`.
- Provider responses should include OIDC `redirectURI` compatibility metadata
  where upstream returns it.

### OIDC Discovery And Callback

- Runtime discovery must hydrate incomplete stored OIDC config during sign-in
  and callback, not only during registration.
- Discovery must produce stable error codes matching upstream semantics:
  `discovery_invalid_url`, `discovery_untrusted_origin`,
  `discovery_not_found`, `discovery_timeout`, `discovery_invalid_json`,
  `discovery_incomplete`, `issuer_mismatch`, and
  `discovery_unexpected_error`.
- Discovery URL validation must reject untrusted origins using OpenAuth trusted
  origin policy, and discovered endpoints must remain on trusted origins.
- Discovery fetch must have the upstream 10 second timeout behavior.
- OIDC callback must support ID-token-only profile extraction when
  `userInfoEndpoint` is absent.
- OIDC callback must redirect new users to `newUserCallbackURL` when provided.
- OIDC callback must preserve mapped `extraFields` once OpenAuth core exposes a
  typed place for raw provider attributes.

### SAML Pipeline

- ACS redirect targets must be normalized through a safe redirect helper:
  reject untrusted absolute URLs, protocol-relative URLs, and redirect loops
  back into callback/ACS paths.
- RelayState should use OpenAuth generic state/cookie semantics where possible,
  with cross-site POST cookie checks intentionally skipped for ACS.
- SAML callback GET parity is still missing: upstream uses it for browser flow
  session/RelayState handling.
- ACS must convert structural 400 flow errors to browser redirects with error
  query parameters where upstream does, while preserving true 404/401/403
  failures.
- SAML AuthnRequest signing must use SP private key material behind the SAML
  signature boundary and include `Signature`/`SigAlg` in Redirect binding URLs.
- Encrypted assertions must fail closed in default builds. With `saml-signed`
  and explicit `decryptionPvk`, ACS must decrypt exactly one encrypted
  assertion before user provisioning and reject missing/invalid keys before
  creating users or sessions.
- Runtime SAML algorithm validation must inspect parsed responses for signature,
  digest, key-encryption, and data-encryption algorithms, not only configured
  provider fields.

### SAML Metadata And SLO

- SP metadata must use configured `spMetadata.metadata` directly when supplied.
- Generated SP metadata must include SingleLogoutService POST and Redirect
  bindings when SLO is enabled.
- Generated SP metadata must include `wantMessageSigned`,
  `authnRequestsSigned`, and configured `NameIDFormat`.
- Metadata endpoint query `format=json` should either be implemented or
  explicitly rejected/tested as unsupported.
- SLO should use configured IdP SLO service endpoints when present, instead of
  assuming `entryPoint`.
- SLO POST-form responses are not implemented; current behavior is redirect
  only.
- The global sign-out hook that clears SAML session lookup records is still
  pending.

### Domain Verification And State Storage

- Domain verification should support OpenAuth secondary storage when configured,
  falling back to database verification storage.
- Request/verify endpoints must check org membership/admin access for
  organization-linked providers.
- DNS hostname extraction should keep supporting bare domains and URLs, and
  should receive dedicated tests for multi-domain providers.

### OpenAPI And Modularization

- OpenAPI metadata is still minimal. Each endpoint needs upstream-equivalent
  summaries, descriptions, request schemas, response descriptions, and hidden
  metadata for browser callbacks/SLO where appropriate.
- `routes/mod.rs` is intentionally functional but too large now. Split it into
  focused route modules before adding more behavior:
  `routes::registration`, `routes::providers`, `routes::sign_in`,
  `routes::oidc`, `routes::saml_acs`, `routes::slo`, and
  `routes::domain_verification`.
