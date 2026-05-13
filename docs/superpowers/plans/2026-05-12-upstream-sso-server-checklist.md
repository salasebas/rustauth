# Upstream SSO Server Checklist Plan

> This document is a reusable implementation guide, not a strict port contract. If an implementation adds behavior that covers the same requirement more correctly, more securely, or more idiomatically for Rust/OpenAuth, mark the checklist item as completed and document the stronger behavior in the implementation notes.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the server-side behavior of Better Auth `packages/sso` into an idiomatic Rust SSO package/checklist, excluding browser-only and TypeScript-only client surfaces.

**Architecture:** Treat upstream as product and behavior reference, not as structure to copy. Split the Rust implementation around typed config, provider storage, OIDC discovery/login, SAML login/security, SLO, domain verification, organization assignment, and tests.

**Tech Stack:** Rust, HTTP server integration, typed storage adapter contracts, OIDC/OAuth2, JOSE/JWT, SAML 2.0 XML parsing/signature validation, DNS TXT verification, X.509 certificate parsing.

---

## Scope

Upstream package analyzed: `upstream/better-auth/1.6.9/repository/packages/sso`.

Server-side source included:

- `src/index.ts`
- `src/constants.ts`
- `src/types.ts`
- `src/routes/sso.ts`
- `src/routes/providers.ts`
- `src/routes/domain-verification.ts`
- `src/routes/helpers.ts`
- `src/routes/saml-pipeline.ts`
- `src/routes/schemas.ts`
- `src/saml-state.ts`
- `src/oidc/*`
- `src/saml/*`
- `src/linking/*`
- `src/utils.ts`
- server behavior covered by upstream tests in `src/*.test.ts`, `src/oidc/*.test.ts`, `src/saml/*.test.ts`, `src/linking/*.test.ts`

Server-side source excluded:

- `src/client.ts`: Better Auth client plugin/type inference only.
- `README.md`, `CHANGELOG.md`, `tsconfig.json`, `tsdown.config.ts`, `vitest.config.ts`, package build metadata.

Important note: this checklist is based only on upstream SSO. It does not inspect current OpenAuth implementation status.

## Upstream Dependency Equivalents To Decide

- [ ] HTTP endpoint/routing abstraction: upstream `better-auth/api` (`createAuthEndpoint`, middleware, redirects, API errors). Rust needs OpenAuth endpoint/router equivalent.
- [ ] Session cookies and session lookup: upstream `better-auth/cookies`, `getSessionFromCtx`, `sessionMiddleware`, `internalAdapter.deleteSession`. Rust needs server-side cookie/session primitives.
- [ ] OAuth2/OIDC authorization-code flow: upstream `better-auth` and `better-auth/oauth2` (`createAuthorizationURL`, `validateAuthorizationCode`, `validateToken`, `handleOAuthUserInfo`). Rust needs OAuth2 URL generation, token exchange, ID token validation, account linking/session creation.
- [ ] Random state/token generation: upstream `better-auth/crypto`. Rust needs cryptographically secure random strings.
- [ ] State storage: upstream `generateState`, `parseState`, `generateGenericState`, `parseGenericState`. Rust needs state/relay-state persistence with TTL and cookie behavior where applicable.
- [ ] Base64 decoding for SAML response pre-validation: upstream `@better-auth/utils/base64`. Rust needs strict base64 decoding that tolerates SAML line wrapping only after whitespace normalization.
- [ ] Typed API error-code helpers: upstream `@better-auth/core/utils/error-codes`. Rust needs stable SAML/SSO error codes, not only display strings.
- [ ] Storage adapter abstraction: upstream `@better-auth/core/db/adapter`. Rust needs adapter traits for provider records, members, sessions, verification values, and count/find/update/delete operations used by SSO.
- [ ] HTTP client for OIDC discovery and UserInfo: upstream `@better-fetch/fetch`. Rust needs a maintained async HTTP client.
- [ ] JOSE/JWT: upstream `jose` (`decodeJwt`, token validation via Better Auth). Rust needs JWT decode and JWK signature validation.
- [ ] XML parsing and validation: upstream `fast-xml-parser`. Rust needs secure XML parsing with entity expansion disabled and namespace-aware extraction.
- [ ] SAML toolkit: upstream `samlify`. Rust needs SAML SP/IdP metadata, AuthnRequest, LogoutRequest/Response, signature, binding, and parsing support or an owned abstraction over selected crates.
- [ ] DNS TXT lookup: upstream Node `dns/promises`. Rust needs async DNS TXT resolution.
- [ ] Domain hostname parsing: upstream `tldts`. Rust needs robust public-suffix/domain parsing.
- [ ] X.509 certificate parsing: upstream Node `X509Certificate`. Rust needs certificate parsing for fingerprint, validity, and public key algorithm.
- [ ] Schema validation: upstream `zod`. Rust needs typed request structs plus validation at API boundaries.
- [ ] Test harness equivalents: upstream tests use `vitest`, `better-auth/test`, `memoryAdapter`, `oauth2-mock-server`, `express`, and `body-parser`. Rust needs local test servers, in-memory adapters, form-urlencoded body support, mocked OAuth/OIDC providers, and SAML IdP/SP fixtures.

## Storage And Schema Checklist

- [ ] SSO provider storage model `ssoProvider`.
- [ ] Provider field `issuer`, required string.
- [ ] Provider field `oidcConfig`, optional serialized OIDC config.
- [ ] Provider field `samlConfig`, optional serialized SAML config.
- [ ] Provider field `userId`, user reference.
- [ ] Provider field `providerId`, required unique string.
- [ ] Provider field `organizationId`, optional string.
- [ ] Provider field `domain`, required string, supports comma-separated domains.
- [ ] Provider field `domainVerified`, optional boolean when domain verification is enabled.
- [ ] Field-name mapping option for `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`, `organizationId`, and `domain`.
- [ ] Verification storage for SAML AuthnRequest IDs with prefix `saml-authn-request:`.
- [ ] Verification storage for used SAML assertion IDs with prefix `saml-used-assertion:`.
- [ ] Verification storage for SAML session lookup by provider/nameID with prefix `saml-session:`.
- [ ] Verification storage for reverse SAML session lookup by session ID with prefix `saml-session-by-id:`.
- [ ] Verification storage for LogoutRequest IDs with prefix `saml-logout-request:`.
- [ ] Domain verification token storage with identifier `_<tokenPrefix>-<providerId>`.
- [ ] Support verification storage backed by primary database.
- [ ] Support verification storage backed by secondary storage.
- [ ] Store provider OIDC/SAML configs without leaking secrets through read endpoints.

## Public Plugin Surface Checklist

- [ ] SSO plugin registration with id `sso`.
- [ ] Package/version exposure equivalent.
- [ ] Endpoint declarations use the OpenAuth equivalent of upstream `createAuthEndpoint` so method, path, request schema, middleware, allowed media types, hidden/public metadata, and OpenAPI metadata live with the handler.
- [ ] Public endpoints include OpenAPI metadata equivalent to upstream `operationId`, summary, description, request body details, and response descriptions where upstream provides them.
- [ ] Internal/browser-callback endpoints preserve upstream hidden-metadata behavior where appropriate instead of exposing noisy public API docs.
- [ ] Authenticated endpoints attach session middleware or an equivalent typed session extractor at the route boundary.
- [ ] Form POST endpoints accept `application/x-www-form-urlencoded` in addition to JSON where upstream allows it.
- [ ] Server endpoints registered:
  - [ ] `GET /sso/saml2/sp/metadata`
  - [ ] `POST /sso/register`
  - [ ] `POST /sign-in/sso`
  - [ ] `GET /sso/callback/:providerId`
  - [ ] `GET /sso/callback`
  - [ ] `GET|POST /sso/saml2/callback/:providerId`
  - [ ] `POST /sso/saml2/sp/acs/:providerId`
  - [ ] `GET|POST /sso/saml2/sp/slo/:providerId`
  - [ ] `POST /sso/saml2/logout/:providerId`
  - [ ] `GET /sso/providers`
  - [ ] `GET /sso/get-provider`
  - [ ] `POST /sso/update-provider`
  - [ ] `POST /sso/delete-provider`
  - [ ] `POST /sso/request-domain-verification`, only when domain verification is enabled.
  - [ ] `POST /sso/verify-domain`, only when domain verification is enabled.
- [ ] Endpoint request/response metadata:
  - [ ] `getSSOServiceProviderMetadata` for SP metadata.
  - [ ] `registerSSOProvider` for provider registration.
  - [ ] `signInWithSSO` for SSO sign-in.
  - [ ] `handleSSOCallback` for per-provider OIDC callback.
  - [ ] `handleSSOCallbackShared` for shared OIDC callback.
  - [ ] `handleSAMLCallback` for SAML callback.
  - [ ] `handleSAMLAssertionConsumerService` for ACS.
  - [ ] `listSSOProviders` for provider list.
  - [ ] `getSSOProvider` for provider detail.
  - [ ] `updateSSOProvider` for provider update.
  - [ ] `deleteSSOProvider` for provider delete.
  - [ ] Domain verification request/verify endpoints include documented 201/204, 404, 409, 502 responses.
- [ ] SAML POST endpoints skip origin check for IdP callbacks:
  - [ ] `/sso/saml2/callback`
  - [ ] `/sso/saml2/sp/acs`
  - [ ] `/sso/saml2/sp/slo`
- [ ] Before sign-out hook removes SAML SLO session verification records when SLO is enabled.
- [ ] After OAuth callback hook can assign organization by verified SSO domain when organization plugin is present.
- [ ] Public Rust API exports SSO config types, provider types, SAML algorithm constants, timestamp validation config, discovery helpers, and error types that make sense for OpenAuth.

## Typed Config Checklist

- [ ] Request structs are separate from persisted config structs where upstream schema permits partial/registration-only fields such as `skipDiscovery`.
- [ ] `OIDCMapping`: id, email, emailVerified, name, image, extraFields.
- [ ] `SAMLMapping`: id, email, emailVerified, name, firstName, lastName, extraFields.
- [ ] `OIDCConfig`: issuer, pkce, clientId, clientSecret, authorizationEndpoint, discoveryEndpoint, userInfoEndpoint, scopes, overrideUserInfo, tokenEndpoint, tokenEndpointAuthentication, jwksEndpoint, mapping.
- [ ] OIDC registration request supports `skipDiscovery` even though it is not persisted into `OIDCConfig`.
- [ ] OIDC token endpoint auth methods: `client_secret_basic`, `client_secret_post`.
- [ ] `SAMLConfig`: issuer, entryPoint, cert, callbackUrl, audience, idpMetadata, spMetadata, signing options, identifier format, private key, decryption key, additional params, mapping.
- [ ] IdP metadata fields: metadata XML, entityID, entityURL, redirectURL, cert, privateKey, privateKeyPass, assertion encryption flags/keys, SSO services, SLO services.
- [ ] SP metadata fields: metadata XML, entityID, binding, private keys, assertion encryption flags/keys.
- [ ] `AuthnRequestRecord`: id, providerId, createdAt, expiresAt.
- [ ] `SAMLSessionRecord`: sessionId, providerId, nameID, sessionIndex.
- [ ] `SAMLAssertionExtract`: nameID, sessionIndex, inResponseTo, conditions.
- [ ] `SSOProvider` with domain verification specialization.
- [ ] `SSOOptions.provisionUser`.
- [ ] `SSOOptions.provisionUserOnEveryLogin`.
- [ ] `SSOOptions.organizationProvisioning.disabled`.
- [ ] `SSOOptions.organizationProvisioning.defaultRole`.
- [ ] `SSOOptions.organizationProvisioning.getRole`.
- [ ] `SSOOptions.defaultSSO`.
- [ ] `SSOOptions.defaultOverrideUserInfo`.
- [ ] `SSOOptions.disableImplicitSignUp`.
- [ ] `SSOOptions.providersLimit`, static or callback.
- [ ] `SSOOptions.trustEmailVerified`, with explicit security warning in docs/API.
- [ ] `SSOOptions.domainVerification.enabled`.
- [ ] `SSOOptions.domainVerification.tokenPrefix`.
- [ ] `SSOOptions.redirectURI` shared OIDC callback.
- [ ] `SSOOptions.saml.enableInResponseToValidation`.
- [ ] `SSOOptions.saml.allowIdpInitiated`.
- [ ] `SSOOptions.saml.requestTTL`.
- [ ] `SSOOptions.saml.clockSkew`.
- [ ] `SSOOptions.saml.requireTimestamps`.
- [ ] `SSOOptions.saml.algorithms`.
- [ ] `SSOOptions.saml.maxResponseSize`.
- [ ] `SSOOptions.saml.maxMetadataSize`.
- [ ] `SSOOptions.saml.enableSingleLogout`.
- [ ] `SSOOptions.saml.logoutRequestTTL`.
- [ ] `SSOOptions.saml.wantLogoutRequestSigned`.
- [ ] `SSOOptions.saml.wantLogoutResponseSigned`.

## Constants Checklist

- [ ] Default AuthnRequest TTL: 5 minutes.
- [ ] Default used assertion TTL: 15 minutes.
- [ ] Default LogoutRequest TTL: 5 minutes.
- [ ] Default SAML clock skew: 5 minutes.
- [ ] Default max SAML response size: 256 KB.
- [ ] Default max SAML IdP metadata size: 100 KB.
- [ ] SAML success status URI: `urn:oasis:names:tc:SAML:2.0:status:Success`.
- [ ] Verification key prefixes match behavior, though Rust names can be idiomatic.

## Modularization Checklist

- [ ] Keep the Rust SSO package split into focused modules rather than one large endpoint file.
- [ ] Suggested module: `config` or `types` for public config, mappings, provider structs, and option builders.
- [ ] Suggested module: `storage` for provider/member/session/verification adapter traits and serialized config conversions.
- [ ] Suggested module: `routes::providers` for list/get/update/delete provider endpoints.
- [ ] Suggested module: `routes::registration` for provider registration and request validation, or keep with providers only if still small.
- [ ] Suggested module: `routes::domain_verification` for DNS token request/verify endpoints.
- [ ] Suggested module: `oidc::discovery` for discovery URL compute, fetch, validation, normalization, hydration, and error mapping.
- [ ] Suggested module: `oidc::flow` for OIDC sign-in and callback behavior.
- [ ] Suggested module: `saml::metadata` for SP/IdP metadata construction and SAML toolkit boundary.
- [ ] Suggested module: `saml::pipeline` for SAML response processing, redirect safety, account linking, replay protection, and session creation.
- [ ] Suggested module: `saml::security` for timestamp, algorithm, single assertion, XML parser, and replay helpers.
- [ ] Suggested module: `saml::slo` for SAML Single Logout endpoints and records.
- [ ] Suggested module: `linking` for organization assignment from provider and domain.
- [ ] Suggested module: `utils` only for small pure helpers such as domain matching, JSON/config parsing, certificate summaries, and client ID masking.
- [ ] Test modules mirror source modules so security-sensitive behavior can be reviewed independently.

## Provider Management Endpoints Checklist

- [ ] `GET /sso/providers` requires authenticated session.
- [ ] Returns only user-owned providers when no organization plugin is available.
- [ ] Returns organization providers only to org admins/owners when organization plugin is enabled.
- [ ] Parses comma-separated roles and accepts `owner` and `admin`.
- [ ] Returns empty list when no accessible providers exist.
- [ ] Sanitizes OIDC provider config on list/read.
- [ ] Masks OIDC client ID to last four characters, or all asterisks for short IDs.
- [ ] Never returns OIDC client secret.
- [ ] Sanitizes SAML provider config on list/read.
- [ ] Returns SAML certificate metadata only: SHA-256 fingerprint, validity, public key algorithm.
- [ ] Handles certificate parse errors without leaking raw PEM.
- [ ] Adds SP metadata URL for provider responses.
- [ ] `GET /sso/get-provider` requires authenticated session.
- [ ] Returns 404 when provider is missing.
- [ ] Returns 403 when user lacks provider access.
- [ ] Applies same owner/admin access rules as list.
- [ ] `POST /sso/update-provider` requires authenticated session.
- [ ] Requires at least one update field.
- [ ] Updates issuer.
- [ ] Updates domain.
- [ ] Resets `domainVerified` to false when domain changes.
- [ ] Partially merges SAML config without dropping existing required values.
- [ ] Partially merges OIDC config without dropping existing required values.
- [ ] Rejects SAML config update on a provider without SAML config.
- [ ] Rejects OIDC config update on a provider without OIDC config.
- [ ] Validates issuer URL on update.
- [ ] Enforces SAML metadata max size on update.
- [ ] Validates configured SAML signature/digest algorithms on update.
- [ ] Allows org admin to update org provider.
- [ ] Rejects org member update when not admin/owner.
- [ ] `POST /sso/delete-provider` requires authenticated session.
- [ ] Applies same provider access rules before deleting.
- [ ] Deletes provider record.
- [ ] Does not delete linked accounts when provider is deleted.

## Provider Registration Checklist

- [ ] `POST /sso/register` requires authenticated session.
- [ ] Registration request schema validates `providerId`, `issuer`, `domain`, optional OIDC config, optional SAML config, optional `organizationId`, and optional `overrideUserInfo`.
- [ ] OIDC registration schema validates optional endpoint URLs when supplied.
- [ ] OIDC registration schema supports mapping fields and extraFields.
- [ ] SAML registration schema supports mapping fields and extraFields.
- [ ] SAML registration schema supports IdP metadata SSO services with Binding and Location.
- [ ] SAML registration schema supports SP metadata signing/encryption fields.
- [ ] Enforces `providersLimit`, including zero meaning registration disabled.
- [ ] Supports `providersLimit` as callback from user to number.
- [ ] Counts existing providers by user before creating.
- [ ] Validates issuer is a URL.
- [ ] Rejects duplicate `providerId`.
- [ ] If `organizationId` is provided, verifies current user is a member.
- [ ] Persists user-owned provider without organization.
- [ ] Persists organization-linked provider.
- [ ] Supports domain string with comma-separated domains.
- [ ] Supports OIDC provider registration.
- [ ] Supports SAML provider registration.
- [ ] Allows provider to include both OIDC and SAML configs, while login can choose by `providerType`.
- [ ] For domain verification enabled, initializes `domainVerified=false`.
- [ ] For domain verification enabled, returns a one-week verification token.
- [ ] Returns OIDC redirect URI based on provider-specific callback when no shared redirect URI is configured.
- [ ] Returns shared OIDC redirect URI when `redirectURI` option is configured.
- [ ] Supports `overrideUserInfo` per provider or `defaultOverrideUserInfo`.
- [ ] Validates SAML IdP metadata size.
- [ ] Validates SAML config algorithms.
- [ ] Rejects SAML config without usable IdP entry point: metadata XML, SSO service, or valid `entryPoint`.
- [ ] Supports SAML `idpMetadata` fallback fields when metadata XML is absent.
- [ ] Supports SAML custom fields/storage mappings.

## OIDC Discovery Checklist

- [ ] Discovery request timeout defaults to 10 seconds.
- [ ] Compute discovery URL as `<issuer>/.well-known/openid-configuration`.
- [ ] Preserve issuer path when computing discovery URL.
- [ ] Validate discovery URL syntax.
- [ ] Reject non-HTTP/HTTPS discovery URLs.
- [ ] Reject untrusted discovery origin.
- [ ] Fetch discovery document with timeout.
- [ ] Map 404 to `discovery_not_found`.
- [ ] Map timeout/abort/408 to `discovery_timeout`.
- [ ] Map invalid JSON or empty body to `discovery_invalid_json`.
- [ ] Map other HTTP/server errors to `discovery_unexpected_error`.
- [ ] Require discovery fields: issuer, authorization_endpoint, token_endpoint, jwks_uri.
- [ ] Report all missing required fields.
- [ ] Validate exact issuer match, normalizing trailing slash only.
- [ ] Normalize relative discovery endpoint URLs against issuer.
- [ ] Validate normalized discovered URLs are trusted.
- [ ] Handle optional userinfo, revocation, end_session, introspection endpoints.
- [ ] Select token endpoint auth method, preferring existing config.
- [ ] Prefer `client_secret_basic` when both supported.
- [ ] Use `client_secret_post` when only that supported.
- [ ] Default to `client_secret_basic` for unsupported or unspecified methods.
- [ ] Hydrate config from discovery at registration time when `skipDiscovery` is false.
- [ ] Allow `skipDiscovery` with explicit endpoints.
- [ ] Support custom discovery endpoint in request.
- [ ] Support discovery endpoint from existing config.
- [ ] Preserve existing explicit config values over discovery values.
- [ ] Include `scopes_supported`/supported scopes where useful in Rust config.
- [ ] Determine when runtime discovery is needed: missing authorization, token, or JWKS endpoint.
- [ ] Runtime discovery fills missing endpoints before sign-in/callback.
- [ ] Map discovery errors to API responses at endpoint boundaries.

## OIDC Login And Callback Checklist

- [ ] `POST /sign-in/sso` accepts email, organizationSlug, providerId, domain, callbackURL, errorCallbackURL, newUserCallbackURL, scopes, loginHint, requestSignUp, providerType.
- [ ] Requires one provider selector unless `defaultSSO` is configured.
- [ ] Derives domain from email when domain is omitted.
- [ ] Resolves organization slug to organization ID.
- [ ] Resolves provider by `defaultSSO` providerId.
- [ ] Resolves provider by `defaultSSO` domain.
- [ ] Resolves database provider by providerId.
- [ ] Resolves database provider by organizationId.
- [ ] Resolves database provider by exact domain.
- [ ] Resolves database provider by comma-separated domain match.
- [ ] Rejects missing provider.
- [ ] Rejects providerType `oidc` when OIDC config is absent.
- [ ] Rejects providerType `saml` when SAML config is absent.
- [ ] Enforces domain verification before login when enabled.
- [ ] Runs runtime discovery for incomplete OIDC config.
- [ ] Rejects OIDC config missing authorization endpoint.
- [ ] Generates OAuth state.
- [ ] Includes `ssoProviderId` in state for shared redirect URI.
- [ ] Supports PKCE code verifier when configured.
- [ ] Uses default scopes `openid`, `email`, `profile`, `offline_access`.
- [ ] Allows request scopes to override provider scopes.
- [ ] Sends login hint from request or email.
- [ ] Builds provider-specific redirect URI `/sso/callback/:providerId`.
- [ ] Builds shared redirect URI from configured path or full URL.
- [ ] Returns authorization URL and redirect flag.
- [ ] `GET /sso/callback/:providerId` handles per-provider OIDC callback.
- [ ] `GET /sso/callback` handles shared callback by reading provider ID from state.
- [ ] Validates OAuth state.
- [ ] Redirects invalid state to configured error URL.
- [ ] Redirects provider errors to error/callback URL with description.
- [ ] Exchanges authorization code for tokens using configured token endpoint auth.
- [ ] Supports `client_secret_basic` token exchange.
- [ ] Supports `client_secret_post` token exchange.
- [ ] Fetches UserInfo endpoint with bearer access token when configured.
- [ ] Falls back to ID token claims when UserInfo endpoint is absent.
- [ ] Validates ID token with JWKS endpoint, audience, and issuer.
- [ ] Rejects missing JWKS endpoint when using ID token.
- [ ] Applies OIDC field mapping.
- [ ] Applies OIDC extra field mapping.
- [ ] Requires user ID and email.
- [ ] Lowercases or otherwise normalizes email to prevent duplicate users.
- [ ] Honors `trustEmailVerified` only when configured.
- [ ] Computes trusted provider from verified domain plus email domain match.
- [ ] Calls OAuth account/user handling with account tokens and provider ID.
- [ ] Honors `disableImplicitSignUp` unless `requestSignUp` is true.
- [ ] Honors `overrideUserInfo`.
- [ ] Calls `provisionUser` for new user registration.
- [ ] Calls `provisionUser` on every login when `provisionUserOnEveryLogin` is true.
- [ ] Assigns organization from linked provider after OIDC login.
- [ ] Sets session cookie.
- [ ] Redirects to `newUserCallbackURL` for new users when provided.
- [ ] Redirects to `callbackURL` for existing users.
- [ ] Supports defaultSSO OIDC with providerId, email domain, explicit endpoints, and discovery.
- [ ] Supports OIDC UserInfo-only flow where UserInfo `sub` supplies account ID and no ID token is returned.

## SAML Metadata And Helpers Checklist

- [ ] `GET /sso/saml2/sp/metadata` validates query `providerId`.
- [ ] `GET /sso/saml2/sp/metadata` accepts `format` query values `xml` or `json` with default `xml`; if Rust does not support JSON metadata output, document and test the chosen behavior explicitly.
- [ ] XML schema validator equivalent for SAML XML validation.
- [ ] Service Provider metadata endpoint reads provider by providerId.
- [ ] Rejects missing provider.
- [ ] Rejects invalid SAML config.
- [ ] Generates SP metadata from configured SP metadata XML when provided.
- [ ] Generates SP metadata from typed SP fields when metadata XML is absent.
- [ ] Includes Assertion Consumer Service POST binding.
- [ ] Uses configured callbackUrl or default ACS URL.
- [ ] Includes SingleLogoutService POST and Redirect bindings when SLO is enabled.
- [ ] Includes `wantMessageSigned` from `wantAssertionsSigned`.
- [ ] Includes `authnRequestsSigned`.
- [ ] Includes configured NameID format.
- [ ] `findSAMLProvider` checks `defaultSSO` first by providerId, then database.
- [ ] `findSAMLProvider` parses serialized SAML config.
- [ ] `createSP` builds SP with entityID, ACS, SLO, signing, encryption, NameID format, relay state.
- [ ] `createIdP` builds IdP from metadata XML.
- [ ] `createIdP` builds IdP from entityID, SSO service, SLO service, cert, signing/encryption fields.
- [ ] SAML POST form generation escapes action, field names, SAML value, and RelayState.
- [ ] SAML POST form returns auto-submit HTML with noscript fallback.

## SAML Sign-In Checklist

- [ ] `POST /sign-in/sso` can initiate SAML when provider has SAML config.
- [ ] Validates SAML config can be parsed.
- [ ] Rejects `authnRequestsSigned=true` without private key.
- [ ] Generates RelayState from callbackURL, errorCallbackURL, newUserCallbackURL, requestSignUp, link data, and code verifier.
- [ ] RelayState expires after 10 minutes.
- [ ] Builds SP metadata dynamically when SP metadata XML is absent.
- [ ] Builds SP with private key and relay state.
- [ ] Builds IdP from metadata XML or fallback fields.
- [ ] Creates SAML AuthnRequest using HTTP-Redirect binding.
- [ ] Includes signature and SigAlg for signed AuthnRequests.
- [ ] Includes RelayState in signed URL.
- [ ] Omits signature when AuthnRequests are not signed.
- [ ] Saves AuthnRequest record when InResponseTo validation is enabled.
- [ ] Uses configured request TTL or default 5 minutes.
- [ ] Returns redirect URL and redirect flag.
- [ ] Supports defaultSSO SAML provider fallback.
- [ ] Supports idpMetadata without metadata XML using top-level config fallback.
- [ ] Uses idpMetadata entityID when provided.

## SAML Response Pipeline Checklist

- [ ] SAML response parser uses a dedicated XML parser configuration with attributes preserved, namespace prefixes removed only when safe, and entity processing disabled.
- [ ] Unified SAML response processing for `/sso/saml2/callback/:providerId` and `/sso/saml2/sp/acs/:providerId`.
- [ ] Enforces maximum SAML response size.
- [ ] Normalizes whitespace in base64 SAML response.
- [ ] Parses RelayState while tolerating missing cross-site POST cookie.
- [ ] Looks up provider via defaultSSO then database.
- [ ] Enforces domain verification when enabled.
- [ ] Parses SAML config.
- [ ] Builds SP and IdP from config.
- [ ] Computes safe redirect target from RelayState, provider callbackUrl, or base origin.
- [ ] Prevents redirect loop back to callback/ACS path.
- [ ] Rejects untrusted absolute redirect URLs.
- [ ] Allows safe relative redirect paths.
- [ ] Blocks protocol-relative URLs.
- [ ] Validates exactly one assertion or encrypted assertion.
- [ ] Rejects invalid base64.
- [ ] Rejects non-XML content.
- [ ] Rejects no assertion.
- [ ] Rejects multiple assertions.
- [ ] Rejects XML Signature Wrapping-style extra assertions in nested/extension elements.
- [ ] Parses SAML login response with POST binding.
- [ ] Rejects malformed or failed SAML response validation.
- [ ] Validates SAML response algorithms.
- [ ] Validates SAML timestamps.
- [ ] Enforces InResponseTo validation by default.
- [ ] Accepts valid stored AuthnRequest.
- [ ] Rejects unknown or expired AuthnRequest.
- [ ] Rejects provider mismatch for InResponseTo and deletes the request.
- [ ] Deletes used AuthnRequest after success.
- [ ] Allows IdP-initiated response by default.
- [ ] Rejects IdP-initiated response when `allowIdpInitiated=false`.
- [ ] Skips InResponseTo validation when explicitly disabled.
- [ ] Extracts assertion ID for replay protection.
- [ ] Stores used assertion ID with issuer, providerId, usedAt, expiresAt.
- [ ] Computes replay TTL from NotOnOrAfter plus clock skew when present.
- [ ] Uses default used assertion TTL when NotOnOrAfter is absent.
- [ ] Rejects replayed assertion on callback endpoint.
- [ ] Rejects replayed assertion on ACS endpoint.
- [ ] Rejects cross-endpoint replay between callback and ACS.
- [ ] Logs warning when assertion ID cannot be extracted.
- [ ] Extracts SAML user attributes via mapping.
- [ ] Supports SAML extra field mapping.
- [ ] Uses `nameID` as fallback ID/email.
- [ ] Builds display name from first/last name, displayName, or nameID.
- [ ] Normalizes SAML email to lowercase.
- [ ] Requires extracted user ID and email.
- [ ] Computes trusted provider from configured trusted providers or verified domain match.
- [ ] Calls OAuth/account handling for SAML-backed account with providerId and accountId.
- [ ] Honors `disableImplicitSignUp`.
- [ ] Honors `requestSignUp` from RelayState for SAML sign-up.
- [ ] Calls `provisionUser` for new SAML users.
- [ ] Calls `provisionUser` on every SAML login when configured.
- [ ] Assigns organization from linked provider after SAML login.
- [ ] Sets session cookie.
- [ ] Stores SAML session records for SLO when enabled.
- [ ] Returns safe redirect URL.

## SAML Callback And ACS Endpoints Checklist

- [ ] `GET|POST /sso/saml2/callback/:providerId` supports SP-initiated and IdP-initiated browser flow.
- [ ] SAML callback route is hidden from public metadata while still documenting behavior in developer docs/tests.
- [ ] GET callback requires an existing session.
- [ ] GET callback redirects safely using RelayState query when present.
- [ ] POST callback requires SAMLResponse.
- [ ] POST callback delegates to unified SAML pipeline.
- [ ] `POST /sso/saml2/sp/acs/:providerId` delegates to unified SAML pipeline.
- [ ] ACS route is hidden from public metadata while still preserving allowed form-urlencoded/JSON media types.
- [ ] ACS converts structural SAML 400 errors into browser redirects with error query.
- [ ] ACS preserves non-400 errors such as provider not found or unauthorized.
- [ ] Callback and ACS allow form-urlencoded and JSON bodies.
- [ ] SAML POSTs from external IdP origins are accepted while unrelated POST endpoints remain origin-protected.

## SAML Timestamp And Algorithm Security Checklist

- [ ] `validateSAMLTimestamp` accepts current valid NotBefore/NotOnOrAfter.
- [ ] Applies default 5 minute clock skew.
- [ ] Supports custom clock skew.
- [ ] Rejects NotBefore too far in the future.
- [ ] Rejects expired NotOnOrAfter beyond skew.
- [ ] Handles boundary conditions around clock skew.
- [ ] Accepts missing timestamps by default and logs warning.
- [ ] Rejects missing timestamps when required.
- [ ] Rejects malformed timestamps.
- [ ] Accepts valid ISO 8601 timestamps.
- [ ] Signature algorithm constants: RSA-SHA1, RSA-SHA256/384/512, ECDSA-SHA256/384/512.
- [ ] Digest algorithm constants: SHA1, SHA256/384/512.
- [ ] Key encryption constants: RSA 1.5, RSA-OAEP, RSA-OAEP-SHA256.
- [ ] Data encryption constants: 3DES-CBC, AES-CBC, AES-GCM variants.
- [ ] Runtime response algorithm validation accepts secure signature algorithms.
- [ ] Runtime response algorithm validation warns/rejects/allows deprecated SHA-1 according to config.
- [ ] Runtime response algorithm validation enforces signature allow-list.
- [ ] Runtime response algorithm validation rejects unknown signature algorithms.
- [ ] Runtime encryption validation detects encrypted assertions.
- [ ] Runtime encryption validation warns/rejects/allows deprecated RSA1_5 and 3DES.
- [ ] Runtime encryption validation enforces key/data encryption allow-lists.
- [ ] Config algorithm validation accepts secure signature/digest algorithms.
- [ ] Config algorithm validation handles short-form names like `sha256` and `rsa-sha256`.
- [ ] Config algorithm validation warns/rejects/allows deprecated config algorithms.
- [ ] Config algorithm validation enforces signature/digest allow-lists.
- [ ] Config algorithm validation rejects unknown algorithm names.
- [ ] XML parser disables entity processing.
- [ ] XML tree traversal can count/find namespaced assertion nodes without false positives such as `AssertionConsumerService`.

## SAML Single Logout Checklist

- [ ] SLO is disabled unless explicitly enabled.
- [ ] SLO routes are hidden from public metadata where upstream uses hidden metadata.
- [ ] `GET|POST /sso/saml2/sp/slo/:providerId` rejects requests when SLO is disabled.
- [ ] SLO endpoint accepts SAMLRequest or SAMLResponse from body or query.
- [ ] SLO endpoint rejects missing logout data.
- [ ] SLO endpoint loads SAML provider.
- [ ] SLO endpoint builds SP/IdP with configured logout signature requirements.
- [ ] LogoutResponse handling detects POST vs Redirect binding.
- [ ] LogoutResponse parsing validates response signature/status through SAML toolkit.
- [ ] LogoutResponse rejects invalid response.
- [ ] LogoutResponse rejects non-success status.
- [ ] LogoutResponse checks pending LogoutRequest by InResponseTo.
- [ ] LogoutResponse deletes pending LogoutRequest record.
- [ ] LogoutResponse deletes local session cookie.
- [ ] LogoutResponse redirects to safe RelayState or base URL.
- [ ] LogoutRequest handling detects POST vs Redirect binding.
- [ ] LogoutRequest parsing validates request.
- [ ] LogoutRequest finds SAML session by providerId and NameID.
- [ ] LogoutRequest validates SessionIndex when present.
- [ ] LogoutRequest deletes matching OpenAuth session.
- [ ] LogoutRequest deletes SAML session verification records.
- [ ] LogoutRequest also deletes current session if available.
- [ ] LogoutRequest deletes local session cookie.
- [ ] LogoutRequest creates LogoutResponse with success status and InResponseTo.
- [ ] LogoutRequest returns POST form when POST binding and entity endpoint are available.
- [ ] LogoutRequest redirects for Redirect binding.
- [ ] `POST /sso/saml2/logout/:providerId` requires authenticated session.
- [ ] SP-initiated logout rejects when SLO disabled.
- [ ] SP-initiated logout rejects provider missing.
- [ ] SP-initiated logout rejects IdP without SLO service.
- [ ] SP-initiated logout uses SAML session NameID/SessionIndex when stored.
- [ ] SP-initiated logout falls back to session user email as NameID.
- [ ] SP-initiated logout creates LogoutRequest with callback URL as RelayState.
- [ ] SP-initiated logout stores pending LogoutRequest with TTL.
- [ ] SP-initiated logout deletes SAML session lookup records.
- [ ] SP-initiated logout deletes current session and session cookie.
- [ ] SP metadata includes SingleLogoutService only when SLO is enabled.
- [ ] Sign-out hook clears SAML session verification records.
- [ ] SLO POSTs from external IdP origins bypass origin check.

## Domain Verification Checklist

- [ ] Domain verification endpoints are registered only when enabled.
- [ ] Domain verification request schema validates `providerId`.
- [ ] Default token prefix is `better-auth-token`.
- [ ] Verification identifier is `_<tokenPrefix>-<providerId>`.
- [ ] DNS label length limit is 63 characters.
- [ ] `POST /sso/request-domain-verification` requires session.
- [ ] Request endpoint returns 404 when provider missing.
- [ ] Request endpoint verifies user owns provider.
- [ ] Request endpoint verifies user belongs to provider organization when organizationId is present.
- [ ] Request endpoint rejects already verified domain.
- [ ] Request endpoint reuses existing non-expired token.
- [ ] Request endpoint generates 24-character token.
- [ ] Request endpoint stores token for one week.
- [ ] Request endpoint returns 201 and token.
- [ ] `POST /sso/verify-domain` requires session.
- [ ] Verify endpoint returns 404 when provider missing.
- [ ] Verify endpoint verifies user owns provider.
- [ ] Verify endpoint verifies user belongs to provider organization when organizationId is present.
- [ ] Verify endpoint rejects already verified domain.
- [ ] Verify endpoint checks identifier DNS label length.
- [ ] Verify endpoint rejects missing or expired pending verification.
- [ ] Verify endpoint extracts hostname from bare domains and URLs.
- [ ] Verify endpoint resolves TXT record at `<identifier>.<hostname>`.
- [ ] Verify endpoint accepts TXT value containing `<identifier>=<token>`.
- [ ] Verify endpoint returns bad gateway when DNS lookup/validation fails.
- [ ] Verify endpoint sets provider `domainVerified=true`.
- [ ] Verify endpoint returns 204 on success.
- [ ] Supports custom token prefix.
- [ ] Supports secondary storage verification flow.

## Organization Assignment Checklist

- [ ] Normalized SSO profile shape for SAML/OIDC includes provider type, providerId, accountId, email, emailVerified, name/image, raw attributes.
- [ ] `assignOrganizationFromProvider` returns without provider organizationId.
- [ ] Respects organization provisioning `disabled`.
- [ ] Returns without organization plugin.
- [ ] Skips user when already organization member.
- [ ] Assigns default role `member`.
- [ ] Supports configured default role.
- [ ] Supports async/custom role callback.
- [ ] Passes user, raw userInfo, token, and provider into role callback.
- [ ] Creates member record with organizationId, userId, role, createdAt.
- [ ] `assignOrganizationByDomain` extracts domain from user email.
- [ ] Supports exact domain match.
- [ ] Supports comma-separated and subdomain matching.
- [ ] Requires verified provider when domain verification is enabled.
- [ ] Does not assign unverified provider when verification is enabled.
- [ ] Assigns when verification is disabled even without domainVerified field.
- [ ] Does not assign when provider lacks organizationId.
- [ ] Does not assign when user is already a member.
- [ ] If multiple providers claim same domain, only verified provider is used when verification is enabled.
- [ ] After non-SSO callback, domain-based assignment runs when organization plugin is present.

## Utility Checklist

- [ ] Safe JSON parse returns object values as-is.
- [ ] Safe JSON parse parses serialized JSON strings.
- [ ] Safe JSON parse returns null for null/undefined/empty values.
- [ ] Safe JSON parse errors on invalid JSON string.
- [ ] Domain matching is case-insensitive.
- [ ] Domain matching supports exact domain.
- [ ] Domain matching supports subdomains.
- [ ] Domain matching rejects suffix-only attacks such as `evilcompany.com` for `company.com`.
- [ ] Domain matching supports comma-separated domains.
- [ ] Domain matching trims whitespace and ignores empty domain entries.
- [ ] Email domain validation handles missing email/domain safely.
- [ ] Hostname extraction supports bare domain.
- [ ] Hostname extraction supports full URL.
- [ ] Hostname extraction supports URL with port.
- [ ] Hostname extraction supports subdomain.
- [ ] Hostname extraction supports URL with path.
- [ ] Hostname extraction returns null for empty string.
- [ ] Certificate parser accepts PEM or raw base64 certificate.
- [ ] Certificate parser returns SHA-256 fingerprint, validity dates, and public key algorithm.
- [ ] Client ID masking returns `****last4` for long IDs.
- [ ] Client ID masking returns `****` for IDs of length 4 or shorter.

## Test Coverage Checklist

- [ ] Endpoint metadata tests or snapshot checks cover method/path/schema/OpenAPI exposure for public endpoints and hidden metadata for callback/SAML internals.
- [ ] Body parser tests cover JSON and `application/x-www-form-urlencoded` SAML payloads.
- [ ] In-memory adapter tests cover all provider, member, session, and verification storage operations SSO requires.
- [ ] Provider registration tests for OIDC.
- [ ] Provider registration tests for SAML.
- [ ] Invalid issuer tests.
- [ ] Duplicate providerId tests.
- [ ] Provider limit tests: zero, fixed limit reached, callback limit reached.
- [ ] OIDC sign-in selector tests: email, domain, providerId, organizationSlug.
- [ ] OIDC runtime discovery tests during sign-in.
- [ ] OIDC email normalization test.
- [ ] OIDC disabled implicit sign-up tests.
- [ ] OIDC explicit requestSignUp test.
- [ ] OIDC provisioning tests: once for new users and every-login mode.
- [ ] OIDC shared redirectURI tests: registration response, authorization URL, shared callback completion.
- [ ] OIDC defaultSSO tests: providerId, email domain, explicit endpoints.
- [ ] OIDC UserInfo-only `sub` mapping test.
- [ ] OIDC discovery unit/integration tests for URL compute, validation, document validation, auth method selection, URL normalization, fetch errors, hydration, runtime discovery, trusted-origin enforcement.
- [ ] SAML defaultSSO fallback tests.
- [ ] SAML signed AuthnRequest tests: Signature, SigAlg, RelayState, verifiable signature, missing private key.
- [ ] SAML unsigned AuthnRequest test.
- [ ] SAML IdP metadata fallback tests.
- [ ] SAML provider registration tests.
- [ ] SAML SP metadata tests with/without SLO.
- [ ] SAML login and response handling tests.
- [ ] SAML RelayState validation and fallback tests.
- [ ] SAML disabled implicit sign-up tests.
- [ ] SAML account linking trust tests.
- [ ] SAML InResponseTo tests: reject unsolicited, allow unsolicited default, skip validation, default enabled, verification table.
- [ ] SAML cross-site POST RelayState cookie behavior tests.
- [ ] SAML custom fields/config parsing tests.
- [ ] SAML IdP-initiated GET-after-POST flow tests.
- [ ] SAML safe redirect/open redirect prevention tests.
- [ ] SAML timestamp validation unit tests.
- [ ] SAML origin check bypass tests.
- [ ] SAML forged/unsigned and tampered response rejection tests.
- [ ] SAML size limit constant/export tests.
- [ ] SAML replay protection tests: callback, ACS, cross-endpoint.
- [ ] SAML single assertion/XSW tests.
- [ ] SAML email normalization test.
- [ ] SAML SLO tests: disabled, provider missing, external origin, metadata, SP-initiated, IdP-initiated, LogoutResponse completion.
- [ ] SAML provisioning tests: new-user only and every-login mode.
- [ ] SAML hardening tests: ACS URL consistency, provider lookup fallback, registration validation, RelayState priority.
- [ ] Domain verification endpoint tests for unauthenticated, not found, access denied, token reuse, token creation, already verified, DNS failures, success, custom prefix, bare domain, DNS label limit, secondary storage.
- [ ] Provider read/update/delete endpoint tests for auth, access control, sanitization, partial updates, org admin/member behavior, delete semantics.
- [ ] Organization assignment tests for verified/unverified domains, no organizationId, missing domainVerified, verification disabled, already member, duplicate domain claims.
- [ ] Utility tests for safe JSON parsing, email/domain matching, hostname extraction, certificate parsing, and client ID masking.
- [ ] SAML algorithm tests for runtime response validation, config validation, constants, allow-lists, deprecated behavior, unknown algorithms, short-form names, encrypted assertions.
- [ ] SAML assertion tests for exactly one assertion, encrypted assertion, whitespace base64, no assertion, multiple assertions, XSW patterns, namespace variants, invalid base64, non-XML.

## Rust Design Notes

- [ ] Do not expose TypeScript-shaped generic plugin types in Rust. Provide concrete builder/options structs.
- [ ] Keep client plugin behavior out of the Rust core.
- [ ] Model endpoint errors with typed error enums and HTTP mappings.
- [ ] Use `Result` for fallible parsing, validation, discovery, token exchange, XML/SAML operations, and storage.
- [ ] Treat all redirect inputs as untrusted until checked against trusted origins or same-origin relative path rules.
- [ ] Treat `trustEmailVerified` as risky and document the safer alternatives: trusted providers or verified domain.
- [ ] Keep SAML XML parsing hardened: no entity processing, size limits before parsing, single assertion enforcement before account creation.
- [ ] Hide secrets in all read/list responses.
- [ ] Keep storage contracts explicit enough to support database and secondary verification storage.
- [ ] Prefer small modules: config/types, storage model, providers API, domain verification, OIDC discovery, OIDC flow, SAML metadata, SAML pipeline, SLO, organization linking, utilities, tests.

## Suggested Improvements Beyond Upstream

- [ ] Separate SAML ACS URL from post-auth callback URL in the Rust API. Upstream notes that `callbackUrl` currently doubles as both, which can cause awkward IdP-initiated fallback behavior.
- [ ] Make SP metadata `format=json` either fully implemented or rejected with a clear validation error; upstream accepts the query but returns XML.
- [ ] Use typed secret wrappers for `clientSecret`, private keys, and decryption keys so debug/log output cannot leak them accidentally.
- [ ] Prefer constant-time comparisons for security tokens where practical.
- [ ] Add explicit audit logging hooks for provider registration, update, deletion, domain verification, SAML replay rejection, and SLO session deletion.
- [ ] Add rate limiting hooks around provider registration, domain verification requests, DNS verification attempts, OIDC callback failures, and SAML parse failures.
- [ ] Validate provider domains at registration/update with the same hostname parser used for DNS verification.
- [ ] Add structured error categories for configuration errors vs IdP runtime failures vs suspected attacks.
- [ ] Prefer explicit feature flags for SAML, OIDC discovery, DNS verification, and organization integration if dependencies are heavy or optional.
