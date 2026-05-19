# OpenAuth SSO Design

The SSO crate is an OpenAuth plugin crate. It owns typed options, provider
schema, adapter-backed storage, endpoint handlers, OIDC discovery helpers, SAML
security helpers, SAML state helpers, and provider sanitization.

## Current Module Layout

- `options`: public configuration and builders.
- `schema`: `PluginSchemaContribution` for `ssoProvider`.
- `store`: provider persistence and conversions.
- `routes`: endpoint registration and handlers. This is currently functional
  but too large and should be split before the next broad behavior phase.
- `oidc`: discovery and flow helpers.
- `saml`: metadata, state, timestamp, assertion, signature, logout, and
  algorithm validation.
- `linking`: organization assignment behavior.
- `utils`: small pure helpers for domains, JSON, redirects, and masking.
- SAML endpoint tests mirror route behavior in nested modules so metadata/ACS
  and SLO coverage stays reviewable as parity cases grow.

## Target Module Layout

The next phase should split endpoint code by owned behavior without changing
the public endpoint surface:

- `routes::registration`: `/sso/register`, provider request validation, OIDC
  registration hydration, SAML config validation, initial domain verification
  token creation.
- `routes::providers`: list/get/update/delete, access checks, org admin/member
  policy, provider sanitization response assembly.
- `routes::sign_in`: `/sign-in/sso`, provider selection, defaultSSO matching,
  organization slug lookup, domain verification enforcement.
- `routes::oidc`: OIDC callbacks, runtime discovery, token exchange, ID token
  and UserInfo profile extraction, new-user redirects, provisioning callbacks.
- `routes::saml_acs`: SAML callback/ACS, RelayState parsing, safe redirect
  target selection, response validation, replay protection, session creation.
- `routes::slo`: SAML SLO endpoints and local logout.
- `routes::domain_verification`: request/verify domain ownership and storage
  backend selection.
- `linking::organization`: SSO profile normalization, organization membership
  assignment from OIDC/SAML provider logins, and domain-based organization
  assignment for non-SSO sign-up/sign-in flows.

## Dependency Policy

- Prefer OpenAuth core primitives and workspace dependencies.
- Add heavy OIDC/SAML crates only behind small wrapper boundaries.
- `openidconnect` is included for OIDC issuer URL/discovery/token/id-token
  work.
- `hickory-resolver` is included for DNS TXT domain verification.
- `publicsuffix2` is included to reject public-suffix catchall domain matches.
- `samael` is optional behind the `saml-signed` feature with default features
  disabled, so native XML signature dependencies do not enter the default build.
- Signed SAML XML validation is isolated behind OpenAuth's `saml::signature`
  boundary. The current backend uses the system `xmlsec1` binary for XMLDSig
  verification and `samael` for Redirect binding signature verification because
  `samael`'s in-process XMLSec wrapper is not stable with the local XMLSec/libxml
  stack.
- SAML XML signature processing must stay isolated so native `xmlsec` or a
  future pure-Rust XML security implementation can be swapped without changing
  OpenAuth's public API.
- Generic SAML XML parsing is isolated behind `saml::xml`. OpenAuth validates
  local-name handling, element nesting, parse errors, and rejects `DOCTYPE`
  before extracting assertions, metadata service URLs, logout requests, or
  logout responses. This is the current Rust-side equivalent for upstream
  `samlify` schema-validation coverage until full SAML XSD validation is added.
- Runtime SAML algorithm inspection collects `SignatureMethod`, `DigestMethod`,
  and XML encryption `EncryptionMethod` values from parsed responses. ACS
  validates those values against the configured deprecation policy and optional
  allow-lists before signature verification or user provisioning.
- Signed SAML AuthnRequest Redirect binding is available behind `saml-signed`.
  The default build fails closed for signed request configuration; the signed
  build signs the canonical Redirect query with SP private key material and
  appends `SigAlg` plus `Signature`.
- SAML SP ACS URL selection is explicit through `samlConfig.acsUrl`, with
  `callbackUrl` retained as the backwards-compatible fallback. Metadata,
  AuthnRequest generation, and ACS Destination validation all resolve through
  the same helper.
- OIDC client secrets and SAML private key material use `SecretString` in typed
  Rust config. Persistence serialization still stores the configured material
  for runtime use, but `Debug` output and sanitized provider responses redact or
  omit secrets.
- SSO error observability is centralized in `errors`. Public JSON `code` values
  stay stable, while `sso_error_category` and `sso_error_descriptors` classify
  setup errors, IdP runtime failures, suspected attacks, unsupported paths, and
  unexpected failures for logging or telemetry layers.
- SSO security audit emission is isolated in `audit`. `SsoOptions::audit_event`
  receives typed `SsoAuditEvent` values, while the same helper writes through
  OpenAuth's internal logger. Current events cover provider lifecycle, domain
  verification request/success/failure, SAML replay rejection, SAML signature
  failure, and SLO session deletion.
- SSO contributes plugin rate-limit rules for expensive or attack-prone
  entrypoints: provider registration, domain verification, OIDC callbacks, SAML
  ACS/callback, and SLO endpoints. `SsoRateLimitOptions` keeps defaults
  conservative and allows hosts to disable SSO-contributed rules when they want
  to own all limits through global OpenAuth rate-limit configuration.
- OIDC and SAML `mapping.extraFields` values are exposed through
  `NormalizedSsoProfile.raw_attributes` for provisioning and organization role
  callbacks. The mapped object uses caller-facing extra field names as keys and
  raw provider claim/attribute values as JSON values.
- Non-SSO organization assignment uses SSO plugin after-hooks for successful
  auth endpoints and OpenAuth request-scoped new-session state. It assigns by
  matching the user's email domain to an organization-linked SSO provider,
  requiring `domainVerified` when domain verification is enabled.
- `x509-parser` is included for SAML certificate metadata returned by sanitized
  provider responses. The raw certificate stays internal. If parsing fails,
  sanitized responses expose `certificateError` and omit derived validity/public
  key details instead of returning the raw certificate.

## Security Defaults

- SAML response max size: 256 KiB.
- SAML metadata max size: 100 KiB.
- AuthnRequest/RelayState TTL: 10 minutes.
- Assertion replay TTL: 15 minutes.
- Clock skew: 5 minutes.
- Domain verification token TTL: 7 days.

## Storage Design

- Durable provider configuration stays in `sso_providers` through logical model
  `ssoProvider`.
- Physical database names remain plural and snake_case. Public JSON names remain
  Better Auth-compatible where useful.
- Better Auth's custom field-name mapping option is intentionally not exposed
  for `openauth-sso` right now. OpenAuth keeps one logical provider model and
  lets adapters translate it to physical snake_case/plural storage. Adding a
  second field-mapping layer would make schema generation, migrations, and
  cross-adapter tests less predictable while the crate boundaries are still
  evolving.
- OIDC discovery intentionally stores only endpoints consumed by current SSO
  flows: authorization, token, JWKS, and UserInfo. Optional OP endpoints such as
  `revocation_endpoint`, `end_session_endpoint`, and `introspection_endpoint`
  are not persisted until OpenAuth SSO owns logout/revocation/introspection
  behavior that uses them.
- Ephemeral state should use OpenAuth verification APIs behind a small SSO
  state abstraction:
  - OAuth/OIDC state.
  - SAML AuthnRequest records.
  - Used assertion IDs.
  - SAML session lookup by provider/nameID.
  - Reverse SAML session lookup by OpenAuth session ID.
  - LogoutRequest records.
  - Domain verification tokens.
- The state abstraction should prefer secondary storage when configured and
  fall back to DB verification storage. `SsoStateStore` is the only
  `openauth-sso` boundary that talks to `DbVerificationStore`.

## Access-Control Design

- User-owned providers are accessible only to their owner.
- Organization-linked providers require organization plugin integration:
  - `owner` and `admin` roles can list/get/update/delete providers.
  - Roles may be comma-separated; trim whitespace.
  - Plain members cannot manage providers.
  - If the organization plugin is not installed, fall back to provider `userId`
    ownership to preserve current server-first behavior.
- Registration with `organizationId` requires current-user membership in that
  organization.
- Sign-in by `organizationSlug` resolves the slug to an organization ID and
  selects the linked SSO provider.

## OIDC Design Notes

- Registration-time and runtime discovery hydrate incomplete OIDC configs during
  registration, sign-in, and callback.
- Discovery errors are represented as typed `OidcDiscoveryError` variants with
  stable error codes so routes can map them to API JSON or redirect errors.
- Discovery is fail-closed against OpenAuth trusted origins: the discovery URL
  and discovered authorization, token, JWKS, and UserInfo endpoints must match
  `OpenAuthOptions.trusted_origins`.
- OIDC callback should extract profile data from UserInfo when configured, or
  from ID token claims when UserInfo is absent.
- Trust semantics must stay strict:
  - A provider-asserted `email_verified=true` is not enough for implicit account
    linking unless `trustEmailVerified` is explicitly enabled.
  - Domain-verified SSO providers can be used as the stronger trust signal.

## SAML Design Notes

- Signed XML validation stays behind `saml::signature`.
- SAML parsing uses `quick-xml` with event traversal. Assertion counting also
  uses parser-backed local-name traversal so namespace prefixes, encrypted
  assertions, nested XSW patterns, and metadata fields are handled consistently.
- Encrypted assertions fail closed with
  `ENCRYPTED_SAML_ASSERTION_UNSUPPORTED` by default. With `saml-signed` and an
  explicit `samlConfig.decryptionPvk`, `saml::encryption` uses `samael` behind
  an internal boundary to decrypt exactly one `EncryptedAssertion` into a normal
  assertion before the existing ACS validation and provisioning pipeline runs.
- SAML safe redirects should be centralized in a helper that accepts only:
  - trusted absolute URLs,
  - safe relative paths,
  - no protocol-relative URLs,
  - no callback/ACS loop target.
- SAML metadata should be generated from typed config or returned directly from
  configured metadata XML when present.
- SAML AuthnRequest signing and encrypted assertion decryption require SP
  private key material. These remain optional and isolated from the default
  build.
