# OpenAuth SSO Tasks

## Completed Foundation

- [x] Add spec docs under `docs/superpowers/specs/openauth-sso`.
- [x] Add `openauth_sso::sso(SsoOptions) -> AuthPlugin`.
- [x] Contribute `ssoProvider` schema as `sso_providers` with snake_case fields.
- [x] Register upstream-compatible endpoint surface.
- [x] Implement provider register/list/get/update/delete behavior.
- [x] Validate SAML registration entry points as HTTP(S) URLs before
  persisting providers.
- [x] Validate configured SAML signature/digest algorithms on provider
  registration and update.
- [x] Add SAML algorithm policy options for deprecated algorithm handling and
  signature/digest allow-lists.
- [x] Implement OIDC config persistence and `/sign-in/sso` authorization URL
  generation for configured OIDC providers.
- [x] Implement OIDC callback state/error/no-code redirect handling.
- [x] Implement OIDC callback authorization-code exchange, userinfo mapping,
  account linking, session creation, and redirect cookies.
- [x] Implement domain verification request and DNS TXT verification guards.
- [x] Implement SAML SP metadata endpoint for stored SAML providers.
- [x] Implement OIDC discovery fetch and registration-time hydration.
- [x] Implement OIDC ID token/JWKS validation parity.
- [x] Implement SAML AuthnRequest SP-initiated redirect and verification
  storage.
- [x] Implement SAML ACS request guards for missing/oversized responses.
- [x] Implement SAML ACS unsigned response parsing, timestamp validation, replay
  protection, user mapping, account linking, and session creation when unsigned
  assertions are explicitly allowed.
- [x] Wire `/sso/saml2/callback/:providerId` through the SAML ACS pipeline.
- [x] Persist SAML session lookup records during ACS when Single Logout is
  enabled.
- [x] Implement SAML local logout cleanup for current session and SLO lookup
  records.
- [x] Implement SP-initiated SAML LogoutRequest redirect generation, logout
  request state storage, and local session cleanup.
- [x] Implement SAML LogoutResponse handling and IdP-initiated LogoutRequest
  session cleanup with unsigned XML parsing.
- [x] Add mockable DNS TXT success-path coverage for domain verification.
- [x] Implement SAML ACS cryptographic signature validation and complete signed
  assertion parity.
- [x] Implement cryptographic validation for signed SAML LogoutRequest and
  LogoutResponse messages.
- [x] Reject invalid/public-suffix provider domains at register/update time.
- [x] Return sanitized SAML certificate metadata without exposing raw certs.

## Priority 1: Correctness And Security Gaps

- [x] Fix SSO trust semantics so provider `email_verified=true` does not mark
  the provider trusted unless `SsoOptions.trustEmailVerified` is explicitly
  enabled or a stronger domain-verified trust signal applies.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-core/src/auth/oauth/account_linking.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Add OIDC callback tests for verified email with `trustEmailVerified=false`
    and explicit `trustEmailVerified=true`.
- [x] Add SAML/OIDC safe redirect handling for callback URLs, error URLs, new
  user URLs, RelayState targets, and ACS fallback targets.
  - Files: `crates/openauth-sso/src/utils.rs`,
    `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Cover untrusted absolute URL, protocol-relative URL, relative path success,
    callback/ACS loop rejection, and SLO RelayState fallback.
- [x] Make OIDC callback use `newUserCallbackURL` when
  `handle_oauth_user_info` reports a newly registered user.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
- [x] Replace direct `DbVerificationStore` usage with an SSO state store helper
  that prefers OpenAuth secondary storage when configured and falls back to DB
  verification storage.
  - Files: `crates/openauth-sso/src/state.rs`,
    `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`,
    `crates/openauth-sso/tests/sso/support.rs`.
  - Covers domain verification and SAML AuthnRequest state in secondary storage
    without database `verification` rows.
- [x] Harden SAML assertion counting with XML parser traversal everywhere.
  - Files: `crates/openauth-sso/src/saml/assertions.rs`,
    `crates/openauth-sso/tests/sso/security.rs`.
  - Ported focused upstream `saml/assertions.test.ts` coverage for encrypted
    assertions, namespace prefixes, nested XSW patterns, invalid XML, and
    `AssertionConsumerService` false positives.

## Priority 2: Provider Response And Registration Compatibility

- [x] Add provider response compatibility for upstream `type`.
  - Files: `crates/openauth-sso/src/store.rs`,
    `crates/openauth-sso/tests/sso/endpoints/providers.rs`,
    `crates/openauth-sso/tests/sso/endpoints/registration.rs`.
  - OpenAuth returns both Rust-facing `providerType` and upstream-compatible
    `type`. Covered OIDC and SAML register/list response paths.
- [x] Add OIDC `redirectURI` metadata to registration/provider responses.
  - Files: `crates/openauth-sso/src/store.rs`,
    `crates/openauth-sso/src/routes/registration.rs`,
    `crates/openauth-sso/tests/sso/endpoints/registration.rs`.
  - Covered provider-specific callback URI when `SsoOptions.redirectURI` is not
    set and shared redirect URI when it is configured as a path.
- [x] Decide and cover SAML certificate parse-error response behavior.
  - Files: `crates/openauth-sso/src/store.rs`,
    `crates/openauth-sso/src/utils.rs`,
    `crates/openauth-sso/tests/sso/store.rs`,
    `crates/openauth-sso/tests/sso/endpoints/providers.rs`.
  - Malformed certificates now return sanitized `certificateError` metadata
    without exposing the raw certificate. Covered store and provider list
    responses.
- [x] Add registration tests for providers that include both OIDC and SAML
  config.
  - Files: `crates/openauth-sso/tests/sso/endpoints/registration.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`.
  - Covered dual-config registration, default OIDC sign-in selection, and
    explicit `providerType=saml` selection.
- [x] Decide field-name mapping parity with upstream.
  - Files: `docs/superpowers/specs/openauth-sso/requirements.md`,
    `docs/superpowers/specs/openauth-sso/design.md`,
    `docs/superpowers/specs/openauth-sso/gap-analysis.md`,
    optionally `crates/openauth-sso/src/options.rs`.
  - Documented as intentionally unsupported for now: OpenAuth keeps one logical
    plugin schema and adapter-owned physical snake_case/plural storage names.
- [x] Add form-urlencoded request coverage for public SSO endpoints.
  - Files: `crates/openauth-sso/tests/sso/endpoints/registration.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`.
  - Covered register, sign-in, SAML ACS, and SLO POST using
    `application/x-www-form-urlencoded` request bodies.

## Priority 3: Organization Plugin Parity

- [x] Add provider access policy helpers for organization-linked providers.
  - Files: `crates/openauth-sso/src/org.rs`,
    `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`,
    `crates/openauth-sso/tests/sso/support.rs`.
  - Support `owner` and `admin`, comma-separated roles, and fallback owner
    checks when the organization plugin is absent.
- [x] Update provider list/get/update/delete to use the organization access
  policy.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Ported focused upstream `providers.test.ts` org admin/member cases.
- [x] Validate `organizationId` on provider registration.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/src/org.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Reject registration when current user is not a member.
- [x] Support `/sign-in/sso` selection by `organizationSlug`.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/src/org.rs`,
    `crates/openauth-sso/src/store.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Resolves `organizationSlug` through the organization plugin schema and
    selects the provider by `organizationId`.
- [x] Apply organization membership access to domain verification endpoints.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/src/org.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Allows direct provider owners or organization members to request and verify
    provider domain ownership; rejects unrelated users.
- [x] Return initial domain verification token from provider registration.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Persists the token in `SsoStateStore` and keeps
    `/sso/request-domain-verification` reusable.
- [x] Expand domain verification edge-case coverage.
  - Files: `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Covers custom token prefix, URL-style provider domains, bare domains, and
    already verified conflicts.
- [x] Model organization provisioning options in `SsoOptions`.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/lib.rs`.
  - Added `organizationProvisioning.disabled`,
    `organizationProvisioning.defaultRole`, and async `getRole` callback
    support with exported Rust types.
- [x] Add normalized SSO profile type for organization assignment.
  - Files: `crates/openauth-sso/src/linking.rs` or
    `crates/openauth-sso/src/linking/organization.rs`.
  - Shape includes provider type, provider ID, account ID, email,
    email-verified flag, name/image, raw attributes, and OIDC token data when
    available.
- [x] Implement organization assignment after OIDC and SAML SSO login.
  - Files: `crates/openauth-sso/src/linking.rs` or
    `crates/openauth-sso/src/linking/organization.rs`,
    `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/linking.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Covered no `organizationId` no-op, provisioning disabled no-op, missing
    organization plugin no-op, already-member skip, default `member` role,
    configured default role, async role callback, and OIDC/SAML endpoint
    assignment.
- [x] Add duplicate-domain organization assignment rules.
  - Files: `crates/openauth-sso/src/linking.rs`,
    `crates/openauth-sso/tests/sso/linking.rs`.
  - Domain-based helper assigns only through verified providers when domain
    verification is enabled, including duplicate-domain cases. Also covers
    unverified assignment when verification is disabled.
- [x] Implement domain-based organization assignment for non-SSO auth flows.
  - Files: `crates/openauth-sso/src/linking.rs`,
    `crates/openauth-sso/src/hooks.rs`, `crates/openauth-sso/src/lib.rs`,
    `crates/openauth-sso/tests/sso/endpoints/non_sso_linking.rs`.
  - SSO plugin after-hooks now use OpenAuth request-scoped new-session state
    to assign users by verified SSO provider domain after successful
    `sign-up/email` and `sign-in/email` auth flows. Hook registration also
    covers social/OAuth sign-in endpoints that create non-SSO sessions.

## Priority 4: OIDC Parity

- [x] Mask sanitized OIDC client IDs with upstream-compatible semantics.
  - Files: `crates/openauth-sso/src/utils.rs`,
    `crates/openauth-sso/tests/sso/store.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Returns `****` for short IDs and `****last4` for longer IDs.
- [x] Add `defaultSSO` provider selection for `/sign-in/sso` and both OIDC
  callback endpoints before DB lookup.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Covered providerId matching, domain/email matching, shared callback, and
    path callback.
- [x] Add runtime discovery for incomplete stored OIDC config during sign-in and
  callback.
  - Files: `crates/openauth-sso/src/oidc/discovery.rs`,
    `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/oidc.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Covered defaultSSO and stored providers for sign-in and callback.
- [x] Expand `OidcDiscoveryError` to upstream-compatible stable codes.
  - Include invalid URL, untrusted origin, not found, timeout, invalid JSON,
    incomplete document, issuer mismatch, and unexpected errors.
  - Add fetch timeout default of 10 seconds.
  - Expose stable codes through registration, runtime sign-in JSON errors, and
    OIDC callback redirect errors.
- [x] Validate discovery and discovered endpoint origins against OpenAuth
  trusted-origin policy.
  - Files: `crates/openauth-sso/src/oidc/discovery.rs`,
    `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`,
    `crates/openauth-sso/tests/sso/support.rs`.
  - Registration and runtime discovery now require IdP discovery and discovered
    endpoint origins to be trusted by `OpenAuthOptions.trusted_origins`.
  - Covered untrusted discovery URL rejection and untrusted discovered endpoint
    rejection.
- [x] Support ID-token-only callback profile extraction when UserInfo endpoint
  is absent.
  - Files: `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/endpoints.rs`.
  - Uses claims from a validated ID token as the OAuth profile fallback when no
    UserInfo endpoint is configured.
- [x] Preserve and expose OIDC/SAML `extraFields` mappings once OpenAuth core has
  a typed raw-attributes path.
  - Files: `crates/openauth-core/src/auth/oauth/account_linking.rs`,
    `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Added `OAuthUserInfo.raw_attributes` and populate
    `NormalizedSsoProfile.raw_attributes` from OIDC/SAML `mapping.extraFields`.
    Provisioning callbacks now receive mapped extra field values for both
    provider types.
- [x] Add dynamic `providersLimit` callback support.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/routes/registration.rs`.
  - Implemented as `SsoOptions::providers_limit_callback`, receiving the
    authenticated OpenAuth `User` and resolving an async `usize` limit before
    provider registration. Covered callback limit reached and callback `0`
    registration-disabled behavior.
- [x] Add `provisionUser` and `provisionUserOnEveryLogin` callback support.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Implemented typed async `provisionUser` and
    `provisionUserOnEveryLogin`. Covered OIDC new-user calls, OIDC existing-user
    default skip, OIDC every-login calls, and SAML ACS new-user wiring.
- [x] Add OIDC UserInfo-only callback parity.
  - Files: `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`,
    `crates/openauth-sso/tests/sso/endpoints/helpers.rs`.
  - Existing `auth-code` mock returns no `id_token`; callback coverage asserts
    UserInfo `sub` is used as the account ID.
- [x] Add OIDC email normalization coverage.
  - Files: `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`.
  - Covered mixed-case UserInfo email creating/linking a single lowercase
    OpenAuth user across repeated callbacks.
- [x] Add OIDC `disableImplicitSignUp` and explicit `requestSignUp` coverage.
  - Files: `crates/openauth-sso/src/routes/sign_in.rs`,
    `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`.
  - Covered disabled implicit sign-up rejecting new users and
    `requestSignUp=true` allowing the same OIDC flow by persisting the flag in
    OAuth state.
- [x] Add token endpoint auth behavior coverage.
  - Files: `crates/openauth-sso/src/routes/oidc.rs`,
    `crates/openauth-sso/tests/sso/endpoints/oidc_callback.rs`,
    `crates/openauth-sso/tests/sso/endpoints/helpers.rs`.
  - Covered `client_secret_basic`, `client_secret_post`, and discovery-selected
    fallback to `client_secret_basic` by asserting the raw token request emitted
    by the mock OIDC server.
- [x] Add OIDC sign-in request option coverage.
  - Files: `crates/openauth-sso/src/routes/sign_in.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`.
  - Covered default scopes `openid email profile offline_access`, request scopes
    overriding provider scopes, `loginHint`, and PKCE challenge/state storage.
- [x] Close minor OIDC discovery parity gaps.
  - Files: `crates/openauth-sso/src/oidc/discovery.rs`,
    `crates/openauth-sso/tests/sso/oidc.rs`.
  - Discovery now reports all missing required fields as `discovery_incomplete`
    instead of classifying omitted JSON fields as invalid JSON, and has explicit
    coverage for preserving user-supplied authorization/token/JWKS/UserInfo
    endpoints and token auth over discovered values.
- [x] Decide OIDC discovery optional endpoint storage.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/oidc/discovery.rs`,
    `docs/superpowers/specs/openauth-sso/design.md`.
  - Documented that optional revocation, end-session, and introspection
    endpoints are intentionally not persisted until OpenAuth SSO owns behavior
    that consumes them.

## Priority 5: SAML Config, Metadata, And ACS Parity

- [x] Extend `SamlConfig` with upstream IdP/SP metadata fields.
  - Fields: `idpMetadata`, SP private key/passphrase, encryption flags/keys,
    `privateKey`, `decryptionPvk`, and `additionalParams`.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/store.rs`.
- [x] Validate SAML IdP metadata XML size during register/update.
  - Use `SsoOptions.saml.maxMetadataSize`.
- [x] Allow SAML config entry point from `idpMetadata.metadata` or
  `idpMetadata.singleSignOnService`, not only top-level `entryPoint`.
  - Registration now normalizes `entryPoint` from explicit IdP services or
    metadata XML using parser-backed `SingleSignOnService` extraction, and
    update applies the same metadata-size validation path.
- [x] Implement SP metadata passthrough when `spMetadata.metadata` is supplied.
  - Files: `crates/openauth-sso/src/saml/metadata.rs`,
    `crates/openauth-sso/src/routes/saml_metadata.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Returns configured XML byte-for-byte with `application/xml` and without
    generating ACS/SLO fields on top.
- [x] Enrich generated SP metadata with SLO POST/Redirect bindings,
  `wantMessageSigned`, `authnRequestsSigned`, and `NameIDFormat`.
  - Files: `crates/openauth-sso/src/saml/metadata.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Generated metadata now includes SLO Redirect/POST services when SLO is
    enabled, `AuthnRequestsSigned`, `WantAssertionsSigned`, and configured
    `NameIDFormat`.
- [x] Decide and test metadata `format=json`: either support JSON metadata or
  return a clear unsupported-format error.
  - Current behavior rejects `format=json` explicitly in
    `saml_metadata_endpoint_rejects_json_format_explicitly`.
- [x] Implement SAML AuthnRequest signing when private key material is present.
  - Keep behind the existing SAML signature boundary.
  - Files: `crates/openauth-sso/src/saml/authn_request.rs`,
    `crates/openauth-sso/src/routes/sign_in.rs`,
    `crates/openauth-sso/Cargo.toml`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`.
  - Default build still fails closed with
    `SAML_AUTHN_REQUEST_SIGNING_NOT_SUPPORTED`. With `saml-signed`, signed
    Redirect binding appends `SigAlg` and `Signature`, preserves canonical
    `SAMLRequest`/`RelayState`/`SigAlg` signing order through `samael`, verifies
    in tests with `UrlVerifier`, and rejects missing private key material with
    `SAML_AUTHN_REQUEST_PRIVATE_KEY_REQUIRED`.
- [x] Add SAML GET callback parity for browser flow handling.
  - Files: `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Upstream GET callback requires an existing session and redirects safely
    using RelayState query data. Cover missing session and unsafe RelayState.
- [x] Expand SAML RelayState payload parity.
  - Files: `crates/openauth-sso/src/routes/sign_in.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Cover callbackURL, errorCallbackURL, newUserCallbackURL, requestSignUp,
    account-linking data, PKCE/code-verifier data if applicable, and the
    upstream 10-minute RelayState expiration behavior.
  - Covered stored callback/error/new-user URLs, explicit sign-up intent,
    account creation/linking from the SAML response, and 10-minute RelayState
    expiration. PKCE/code verifier state is not applicable to SAML AuthnRequest
    flow.
- [x] Use `idpMetadata.entityID` when building SAML IdP config.
  - Files: `crates/openauth-sso/src/routes/saml_config.rs`,
    `crates/openauth-sso/src/saml/authn_request.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`.
  - Cover metadata XML absent and `singleSignOnService` present, ensuring
    entity ID does not silently fall back to provider issuer.
- [x] Convert ACS structural 400 errors to browser redirects with error query
  parameters where upstream does.
  - Files: `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/src/routes/support.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Convert missing SAMLResponse, invalid base64, malformed XML, no assertion,
    multiple assertions, expired assertion, unknown AuthnRequest, and replay
    into safe redirect errors when a safe fallback exists. Preserve true 404,
    401, and 403 responses.
- [x] Add encrypted assertion detection/decryption plan behind explicit key
  config; reject encrypted assertions fail-closed until decryption exists.
  - Files: `crates/openauth-sso/src/saml/assertions.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/security.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Exactly one encrypted assertion now fails closed with
    `ENCRYPTED_SAML_ASSERTION_UNSUPPORTED` before provisioning. Mixed
    encrypted/plain assertions still fail the single-assertion guard. Full
    decryption remains a separate explicit-key task.
- [x] Implement encrypted assertion decryption when key config is present.
  - Files: `crates/openauth-sso/src/saml/encryption.rs`,
    `crates/openauth-sso/src/saml/assertions.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/security.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs/state.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs/signed.rs`.
  - Added internal `saml::encryption` boundary. Default builds keep encrypted
    assertions fail-closed even with `decryptionPvk`; `saml-signed` builds use
    `samael` behind the boundary to decrypt exactly one `EncryptedAssertion`
    into a normal assertion before the existing ACS validation/provisioning
    pipeline runs. Invalid keys fail closed before user/session creation.
- [x] Add runtime SAML algorithm validation from parsed response/signature
  metadata, including encryption algorithms.
  - Files: `crates/openauth-sso/src/saml/security.rs`,
    `crates/openauth-sso/src/saml/assertions.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/tests/sso/security.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - SAML responses now collect `SignatureMethod`, `DigestMethod`, and
    `EncryptionMethod` runtime algorithms. ACS validates them before
    signature verification/provisioning using the configured deprecation policy
    plus signature, digest, key-encryption, and data-encryption allow-lists.
    Tests cover SHA-1 rejection, signature allow-list rejection, RSA1_5/3DES
    encryption rejection policy, and ACS browser redirect error parity.
- [x] Add SAML `disableImplicitSignUp` and explicit `requestSignUp` coverage.
  - Files: `crates/openauth-sso/src/routes/sign_in.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Covered disabled implicit sign-up rejecting new users and RelayState
    `requestSignUp=true` allowing the same SAML flow.
- [x] Add SAML email normalization coverage.
  - Files: `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Covered mixed-case SAML emails creating/linking a single lowercase OpenAuth
    user across repeated ACS callbacks.
- [x] Add defaultSSO SAML provider fallback coverage.
  - Files: `crates/openauth-sso/src/routes/sign_in.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - Covered providerId sign-in lookup and callback/ACS provider resolution from
    default SAML providers.
- [x] Add SAML XML validator boundary.
  - Files: `crates/openauth-sso/src/saml/assertions.rs`,
    `crates/openauth-sso/src/saml/logout.rs`,
    `crates/openauth-sso/src/saml/metadata.rs`,
    `crates/openauth-sso/src/saml/signature.rs`,
    `crates/openauth-sso/src/saml/xml.rs`,
    `crates/openauth-sso/tests/sso/security.rs`.
  - `saml::xml` now rejects invalid XML and `DOCTYPE` early, centralizes local
    name extraction, validates SAML response/logout/metadata parsing boundaries,
    and documents the schema-validation equivalent OpenAuth uses instead of
    upstream `samlify` schema validation.
- [x] Add ACS origin-bypass coverage for IdP POSTs.
  - Files: `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`,
    `crates/openauth-sso/tests/sso/support.rs`,
    `crates/openauth-core/src/api/router.rs`,
    `crates/openauth-core/src/api/security.rs`.
  - SAML callback/ACS POSTs can opt into endpoint-level origin-security bypass
    for IdP browser posts while unrelated protected POST endpoints remain
    origin-protected.
- [x] Add assertion replay edge coverage for missing assertion IDs.
  - Files: `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`.
  - OpenAuth fails closed with `INVALID_SAML_RESPONSE` before provisioning,
    account creation, or replay-state writes when assertion ID extraction is
    unavailable.

## Priority 6: SLO And Logout Parity

- [x] Use configured IdP SingleLogoutService endpoints instead of assuming
  `entryPoint`.
  - Files: `crates/openauth-sso/src/saml/logout.rs`,
    `crates/openauth-sso/src/routes/slo.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`.
  - Prefer `idpMetadata.singleLogoutService` by binding and fall back to
    metadata XML extraction. A backward-compatible `entryPoint` fallback remains
    when no IdP metadata is configured.
- [x] Add SLO POST form generation with escaped action/fields and noscript
  fallback.
  - Files: `crates/openauth-sso/src/routes/slo.rs` or
    `crates/openauth-sso/src/saml/logout.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`.
  - Escape action, field names, SAMLRequest/SAMLResponse values, and RelayState.
    Cover POST binding for LogoutRequest and LogoutResponse.
- [x] Add sign-out hook integration to clear SAML session lookup records when
  normal OpenAuth sign-out happens.
  - Files: `crates/openauth-sso/src/hooks.rs`,
    `crates/openauth-sso/src/lib.rs`,
    `crates/openauth-sso/src/routes/slo.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`.
  - The plugin captures the current session before `/sign-out` deletes it, then
    clears `saml-session:*` and `saml-session-by-id:*` records for that session
    after successful sign-out without deleting unrelated SAML sessions.
- [x] Add tests for SLO disabled route behavior, missing logout data, non-success
  LogoutResponse status, pending request mismatch, and SessionIndex mismatch.
  - Also reject unknown LogoutResponse `InResponseTo` values without consuming
    pending logout state, and preserve SAML session lookup state when an
    IdP-initiated LogoutRequest has a mismatched `SessionIndex`.
- [x] Add SLO external-origin POST coverage.
  - Files: `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`,
    `crates/openauth-sso/tests/sso/support.rs`,
    `crates/openauth-sso/src/routes/slo.rs`,
    `crates/openauth-core/src/api/router.rs`.
  - SAML SLO POSTs from IdP origins can opt into endpoint-level
    origin-security bypass while normal protected POST endpoints remain
    origin-protected.
- [x] Add SLO provider/defaultSSO lookup coverage.
  - Files: `crates/openauth-sso/src/routes/slo.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`.
  - Existing stored-provider SLO coverage remains in place; added defaultSSO
    SAML provider lookup for SP-initiated logout.

## Priority 7: Domain Verification And State Coverage

- [x] Domain verification endpoints use `SsoStateStore` and support secondary
  storage.
- [x] Domain verification supports direct provider owners and organization
  members.
- [x] Domain verification supports custom token prefix, URL-style provider
  domains, bare domains, already-verified conflicts, and DNS label limit
  checks.
- [x] Add multi-domain DNS verification coverage.
  - Files: `crates/openauth-sso/src/routes/domain_verification.rs`,
    `crates/openauth-sso/tests/sso/endpoints/domain_verification.rs`.
  - Cover comma-separated provider domains where only one domain has the TXT
    record, and reject empty/invalid entries consistently with registration.
- [x] Add domain verification DNS failure taxonomy coverage.
  - Files: `crates/openauth-sso/src/routes/domain_verification.rs`,
    `crates/openauth-sso/tests/sso/endpoints/domain_verification.rs`.
  - Distinguish resolver transport failure, no TXT records, wrong TXT value,
    and invalid hostname in stable JSON responses.
- [x] Expand utility-domain test coverage.
  - Files: `crates/openauth-sso/src/linking.rs`,
    `crates/openauth-sso/src/utils.rs`,
    `crates/openauth-sso/tests/sso/linking.rs`,
    `crates/openauth-sso/tests/sso/endpoints/domain_verification.rs`.
  - Cover case-insensitive domain matching, comma-separated domains,
    whitespace trimming, suffix-attack rejection, hostname extraction with
    ports and paths, empty hostnames, and URL/bare-domain parity.
- [x] Decide safe JSON parsing utility parity.
  - Files: `crates/openauth-sso/src/utils.rs`,
    `crates/openauth-sso/tests/sso`.
  - Upstream has a safe JSON parser because configs can be serialized strings
    or objects. OpenAuth keeps typed serde at boundaries and now accepts
    adapter-returned `DbValue::Json` config values by serializing them into the
    internal string-backed record before normal typed parsing.

## Priority 8: OpenAPI And Maintainability

- [x] Expand OpenAPI metadata for all SSO endpoints.
  - Files: `crates/openauth-sso/src/openapi.rs`,
    `crates/openauth-sso/src/routes/mod.rs`,
    `crates/openauth-sso/tests/sso/schema.rs`.
  - Include summaries, descriptions, request body fields, response
    descriptions, and hidden metadata for browser callback/SLO endpoints.
- [x] Add endpoint metadata tests for public and hidden SSO routes.
  - Files: `crates/openauth-sso/tests/sso/schema.rs`,
    `crates/openauth-sso/src/openapi.rs`,
    route files under `crates/openauth-sso/src/routes`.
  - Cover method/path/schema exposure for public endpoints and hidden metadata
    for browser callback, ACS, and SLO internals.
- [x] Split `routes/mod.rs` into focused modules before the next broad feature
  phase.
  - Target files: `routes/registration.rs`, `routes/providers.rs`,
    `routes/sign_in.rs`, `routes/oidc.rs`, `routes/saml_acs.rs`,
    `routes/slo.rs`, `routes/domain_verification.rs`, and a thin
    `routes/mod.rs`.
  - Progress: extracted shared response, redirect, auth, query, and path-param
    helpers into `routes/support.rs`; extracted SAML metadata into
    `routes/saml_metadata.rs`; extracted domain verification into
    `routes/domain_verification.rs`; extracted provider list/get/delete into
    `routes/providers.rs`; extracted OIDC callback/runtime discovery into
    `routes/oidc.rs`; extracted provider registration into
    `routes/registration.rs`; extracted provider update/merge behavior into
    `routes/provider_update.rs`; extracted `/sign-in/sso` into
    `routes/sign_in.rs`; extracted SAML ACS into `routes/saml_acs.rs`;
    extracted SAML SLO/logout into `routes/slo.rs`.
    Current `routes/mod.rs` is down to about 125 lines from the previous
    2,300+ line state.
- [x] Split the 4,000+ line `tests/sso/endpoints.rs` into endpoint-domain test
  modules.
  - Files: `tests/sso/endpoints/{providers,domain_verification,provider_update,registration,sign_in,oidc_callback,saml,helpers}.rs`.
  - Keeps shared fixtures/helpers in `endpoints/helpers.rs` and groups behavior
    tests by route family.
- [x] Keep test helper modules below reviewable size.
  - Files: `crates/openauth-sso/tests/sso/endpoints/helpers.rs` and nested
    endpoint test helpers.
  - Split OIDC server/JWT fixtures into
    `tests/sso/endpoints/helpers/oidc_server.rs` and SAML signed XML fixtures
    into `tests/sso/endpoints/helpers/saml_signed.rs`. The main helper module
    is now roughly 615 lines, with focused fixture submodules under 300 lines.
- [x] Split large SAML endpoint test modules by behavior.
  - Files: `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs/*`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/slo/*`.
  - Split metadata/ACS coverage into focused metadata, validation, flow,
    linking, state, signed, and SLO-session modules. Split SLO coverage into
    logout start, configuration, request, response, origin/core, signed, and
    auth modules.
- [x] Keep upstream parity matrix updated after each slice.
  - File: `docs/superpowers/specs/openauth-sso/gap-analysis.md`.
- [x] Add constants/export coverage.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/saml/security.rs`,
    `crates/openauth-sso/tests/sso/security.rs`,
    `crates/openauth/tests/public_api.rs`.
  - Cover default TTLs, max sizes, SAML success status URI, verification key
    prefixes, and public re-exports that are intended to be stable.

## Priority 9: Post-Parity Hardening

- [x] Split SAML ACS URL from post-auth callback URL.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/saml/metadata.rs`,
    `crates/openauth-sso/src/saml/authn_request.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/src/store.rs`,
    `crates/openauth-sso/tests/sso/endpoints/sign_in.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs/metadata.rs`,
    `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs/flows.rs`,
    `crates/openauth-sso/tests/sso/store.rs`.
  - Added `samlConfig.acsUrl` as the explicit Rust-native ACS URL. Metadata,
    AuthnRequest generation, and ACS Destination validation prefer `acsUrl` and
    fall back to existing `callbackUrl` for JSON compatibility. Sanitized SAML
    config exposes `acsUrl` without changing legacy `callbackUrl`.
- [x] Add typed secret wrappers for OIDC client secrets and SAML private keys.
  - Files: `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/store.rs`,
    `crates/openauth-sso/tests/sso/store.rs`.
  - Ensure `Debug` and sanitized response serialization cannot accidentally
    leak secret material.
  - Added `SecretString` for typed config fields covering OIDC client secrets,
    SAML private keys, passphrases, and decryption keys. `Debug` redacts secret
    values; sanitized provider responses continue omitting raw secret material.
    Raw JSON serialization is intentionally preserved for internal provider
    persistence and runtime SSO operations.
- [x] Use constant-time comparison for SSO state and verification tokens where
  practical.
  - Files: `crates/openauth-sso/src/state.rs`,
    `crates/openauth-sso/src/routes/domain_verification.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/src/routes/slo.rs`.
  - Domain verification now compares exact TXT values with `subtle`
    constant-time equality after trimming DNS whitespace, and rejects records
    that only contain the expected token with prefix/suffix data. SAML
    RelayState/logout IDs are used as state-store lookup keys rather than
    in-memory secret comparisons, so they remain adapter lookups.
- [x] Add audit/logging hooks for security-sensitive SSO events.
  - Files: `crates/openauth-sso/src/audit.rs`,
    `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/src/routes/registration.rs`,
    `crates/openauth-sso/src/routes/providers.rs`,
    `crates/openauth-sso/src/routes/provider_update.rs`,
    `crates/openauth-sso/src/routes/domain_verification.rs`,
    `crates/openauth-sso/src/routes/saml_acs.rs`,
    `crates/openauth-sso/src/routes/slo.rs`,
    `crates/openauth-sso/tests/sso/endpoints/audit.rs`.
  - Added `SsoOptions::audit_event` with typed `SsoAuditEvent` values and
    internal logger emission. Covered provider registration/update/delete,
    domain verification request/success/failure, SAML replay rejection, SAML
    signature failure, and SLO session deletion.
- [x] Add rate-limit integration points for expensive or attack-prone SSO
  endpoints.
  - Files: `crates/openauth-sso/src/lib.rs`,
    `crates/openauth-sso/src/options.rs`,
    `crates/openauth-sso/tests/sso/schema.rs`.
  - Cover provider registration, DNS verification attempts, OIDC callback
    failures, and SAML parse/signature failures.
  - Implemented with plugin `PluginRateLimitRule` contributions from
    `SsoRateLimitOptions`: `/sso/register`, domain verification endpoints,
    both OIDC callbacks, SAML ACS/callback, and SLO endpoints. Hosts can disable
    SSO-contributed rules with `SsoOptions::rate_limit_enabled(false)`.
- [x] Add structured error categories for configuration, IdP runtime failure,
  and suspected attack paths.
  - Files: `crates/openauth-sso/src/errors.rs`,
    `crates/openauth-sso/src/routes/*`,
    `crates/openauth-sso/tests/sso/*`.
  - Keep stable JSON codes while allowing observability to distinguish invalid
    setup from malicious input.
  - Added public `SsoErrorCategory`, `SsoErrorDescriptor`,
    `sso_error_category`, and `sso_error_descriptors`. Plugin error code
    registration now derives from the descriptor table while endpoints keep the
    same JSON `code` values.

## Verification Matrix

- [x] `cargo fmt --check`
- [x] `cargo test -p openauth-sso`
- [x] `cargo test -p openauth-sso --features saml-signed`
- [x] `cargo clippy -p openauth-sso --all-targets`
- [x] `cargo clippy -p openauth-sso --features saml-signed --all-targets`
- [x] `cargo test -p openauth --features sso`
