# Better Auth Core Upstream Checklist Implementation Plan

> **Guía de alcance:** Este plan es una guía reutilizable, no una jaula. Si una implementación agrega comportamiento más idiomático, más seguro o más completo que cubre la intención del upstream, el checkbox correspondiente puede marcarse como completado aunque la estructura no sea idéntica a Better Auth.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Crear un checklist reutilizable del paquete upstream `@better-auth/core` para portar solo comportamiento server-side a una implementación Rust.

**Architecture:** Usar `upstream/better-auth/1.6.9/repository/packages/core` como referencia de producto y comportamiento, no como estructura a copiar literalmente. Separar contratos, errores, DB, OAuth/OIDC, providers, contexto, API, utilidades e instrumentación en módulos Rust pequeños con errores tipados y validación explícita.

**Tech Stack:** Rust, Cargo tests, HTTP server abstractions del proyecto destino, serialización tipada, JOSE/JWT/JWKS, almacenamiento primario/secundario, OpenTelemetry opcional.

---

## Scope

Referencia analizada: `upstream/better-auth/1.6.9/repository/packages/core`.

Este checklist ahora empieza a reflejar el estado actual de OpenAuth. Un ítem marcado significa que existe implementación local y cobertura de pruebas observable; la cobertura puede ser idiomática Rust y no una copia exacta de la estructura upstream.

Incluido:

- Server-side core contracts, schemas, adapters, context, API endpoint helpers, errors, OAuth2, social providers, env/logger, instrumentation and security utilities.
- Tests upstream que aplican a comportamiento observable o seguridad.

Excluido:

- `src/types/plugin-client.ts`, porque es client SDK/browser-facing.
- Build/package metadata: `package.json`, `tsconfig.json`, `tsdown.config.ts`, `vitest.config.ts`, `README.md`, `CHANGELOG.md`.
- Cualquier comportamiento que dependa de TypeScript-only typing tricks sin equivalente runtime; se traduce a contratos Rust explícitos.

## Dependency-Driven Functionality

- [ ] `better-call` equivalent: endpoint builder, middleware builder, endpoint context, cookie options, APIError type, APIError header attachment/merge behavior
- [ ] `@better-fetch/fetch` equivalent: typed HTTP client behavior with `data`/`error`, custom headers, body handling, response callback support
- [ ] `@better-auth/utils/base64` equivalent: standard Base64 for OAuth Basic auth
- [ ] `@better-auth/utils/base64url` equivalent: Base64URL without padding for PKCE code challenge and client credentials helper behavior
- [x] `@better-auth/utils/random` equivalent: URL-safe random ID generator with configurable size
- [ ] `jose` equivalent: JWT decode, protected-header decode, JWKS import, remote JWKS verification, local JWK set verification, unsecured JWT decode for introspection payload validation
- [ ] `zod`/`@standard-schema/spec` equivalent: runtime validation for core schemas, IP validation, field validator contracts
- [ ] `kysely` migration concept: plugin migrations and adapter schema generation contract, translated to Rust migration abstractions where applicable
- [ ] DB target concepts from upstream type options: Postgres, MySQL, SQLite, MSSQL, Bun SQLite, Node SQLite, Cloudflare D1, custom adapter instance
- [ ] `node:async_hooks` equivalent: server request/transaction scoped storage
- [ ] Pure async local storage fallback for runtimes without native async local storage
- [ ] OpenTelemetry API equivalent: span creation, status/error recording, semantic DB/HTTP attributes, noop fallback
- [ ] `@vercel/functions`/Cloudflare `waitUntil` concept: background task handler abstraction
- [ ] Test dependency behavior: mocked fetch, generated JWK/JWT test keys, in-memory tracing, async test isolation
- [ ] Client-only dependency exclusion: `nanostores` remains excluded because it appears only in `plugin-client.ts`

## Modularity Requirements

- [x] Keep implementation files modular; do not create a single large Rust file that mirrors upstream `factory.ts`
- [ ] Split DB adapter behavior into focused modules: config defaults, model/field resolvers, ID generation, input transforms, output transforms, where transforms, join transforms, debug logging, operation wrappers, schema creation
- [ ] Split OAuth2 behavior into focused modules: provider contract, authorization URL, authorization-code exchange, refresh token, client credentials, token verification, shared token parsing
- [ ] Split social providers by provider, with shared helpers for repeated OAuth/JWKS/user-mapping patterns
- [ ] Split context behavior into endpoint context, request state, adapter/transaction context, global/version state
- [ ] Split security utilities into IP normalization, host classification, fetch metadata, output filtering, JSON/date parsing
- [ ] Keep browser/client SDK concepts outside core server modules

## Source Map

- [x] Root export surface: `src/index.ts`
- [x] API helpers: `src/api/index.ts`
- [ ] Async local storage abstraction: `src/async_hooks/index.ts`, `src/async_hooks/pure.index.ts`
- [ ] Context: `src/context/endpoint-context.ts`, `src/context/request-state.ts`, `src/context/transaction.ts`, `src/context/global.ts`
- [x] DB schema/contracts: `src/db/**`
- [x] Env/logger: `src/env/**`
- [ ] Errors and error codes: `src/error/**`, `src/utils/error-codes.ts`
- [ ] Instrumentation: `src/instrumentation/**`
- [ ] OAuth2 primitives: `src/oauth2/**`
- [ ] Social providers: `src/social-providers/**`
- [ ] Server-side shared types: `src/types/context.ts`, `src/types/init-options.ts`, `src/types/plugin.ts`, `src/types/cookie.ts`, `src/types/secret.ts`, `src/types/helper.ts`
- [x] Server-side utilities: `src/utils/**`

## Public Module Surface

- [x] Root public types re-export
- [x] `api` public surface
- [ ] `async_hooks` server entry behavior
- [ ] `async_hooks` pure/polyfill behavior for restricted runtimes
- [x] `context` public surface
- [x] `env` public surface
- [x] `error` public surface
- [x] `utils/*` public surface
- [ ] `social-providers` public surface
- [x] `db` public surface
- [x] `db/adapter` public surface
- [ ] `oauth2` public surface
- [ ] `instrumentation` server entry behavior
- [ ] `instrumentation` pure/noop entry behavior

## Core Types And Options

- [ ] Primitive helper types/concepts: awaitable values, literal unions, type flattening equivalents
- [x] Cookie contract: session token, session data, account data, dont-remember token
- [x] Secret rotation config: current version, legacy secret fallback, versioned key map
- [ ] Dynamic base URL config: allowed hosts, fallback, protocol
- [x] Static base URL config
- [x] App metadata: app name, base URL, base path
- [x] Primary secret config
- [x] Versioned secrets config
- [ ] Database option variants and adapter instance config
- [ ] Secondary storage contract: get, set with TTL, delete
- [x] Email verification options and hooks
- [ ] Email/password options: enablement, sign-up policy, email verification requirement
- [x] Password length policy
- [ ] Reset password token policy
- [x] Password hash/verify hooks
- [ ] Auto sign-in after sign-up policy
- [ ] Revoke sessions on password reset policy
- [ ] Existing-user sign-up callback
- [ ] Synthetic user callback for enumeration protection
- [ ] Social providers options map
- [ ] Plugin list option
- [x] User model options and additional fields
- [x] Change-email flow options
- [x] Delete-user flow options
- [x] Session model options and additional fields
- [x] Session expiration, update age and refresh policies
- [ ] Deferred session refresh policy
- [ ] Secondary-storage session persistence policy
- [x] Session cookie cache options: max age, enabled flag, compact/JWT/JWE strategy, refresh cache, version
- [x] Fresh-session age policy
- [x] Account model options and additional fields
- [ ] Account update-on-sign-in policy
- [ ] Account linking policy: enabled, implicit linking, trusted providers, different emails, unlinking all, update user info
- [ ] OAuth token encryption option
- [ ] OAuth state cookie check option
- [ ] OAuth state storage strategy: cookie or database
- [ ] Account cookie storage option
- [x] Verification model options and additional fields
- [ ] Verification cleanup policy
- [ ] Verification identifier storage: plain, hashed, custom hash, per-identifier overrides
- [ ] Verification database storage override with secondary storage
- [x] Trusted origins: static, dynamic and wildcard-aware
- [x] Rate limit options: enabled, window, max, custom rules, storage, custom storage
- [x] Advanced IP options: headers, disable tracking, IPv6 subnet prefix
- [x] Secure cookie policy
- [ ] CSRF disable flag and warning semantics
- [ ] Origin check disable flag and warning semantics
- [x] Cross-subdomain cookie config
- [x] Cookie override config and default cookie attributes
- [x] Cookie prefix config
- [ ] Advanced database options: default limit, ID generation mode/function
- [ ] Trusted proxy headers config
- [ ] Background task handler config
- [x] Skip trailing slashes config
- [ ] API error handling: throw, onError, error URL
- [ ] Server-side default error page customization boundary
- [ ] Global before/after request hooks
- [x] Disabled paths
- [ ] Telemetry options
- [ ] Experimental joins flag

## Plugin Contracts

- [x] Plugin ID and version contract
- [ ] Plugin init hook with context/options mutation
- [ ] Plugin endpoints registration
- [x] Plugin middlewares registration
- [x] Plugin `onRequest` hook
- [x] Plugin `onResponse` hook
- [ ] Plugin before endpoint hooks
- [ ] Plugin after endpoint hooks
- [ ] Plugin DB schema contribution
- [ ] Plugin migrations contribution
- [ ] Plugin options storage
- [ ] Plugin inferred metadata boundary
- [ ] Plugin rate-limit rules
- [ ] Plugin adapter operation overrides
- [ ] Plugin error-code contribution
- [ ] Plugin context lookup by ID
- [ ] Plugin enabled check by ID

## Auth Context And Internal Adapter Contracts

- [ ] Auth info context: app name, base URL, version
- [x] Trusted origins stored on context
- [ ] Trusted providers stored on context
- [x] Trusted-origin verifier
- [ ] OAuth config: state cookie skip and state storage strategy
- [ ] Current session context
- [ ] New session context and setter
- [ ] Social providers list on context
- [x] Auth cookies on context
- [x] Logger on context
- [x] Rate-limit resolved config on context
- [ ] Raw DB adapter on context
- [ ] Internal adapter on context
- [ ] Auth cookie factory on context
- [ ] Internal adapter: create OAuth user
- [ ] Internal adapter: create user
- [ ] Internal adapter: create account
- [ ] Internal adapter: list sessions
- [ ] Internal adapter: list users
- [ ] Internal adapter: count users
- [ ] Internal adapter: delete user
- [ ] Internal adapter: create session
- [ ] Internal adapter: find session
- [ ] Internal adapter: find sessions
- [ ] Internal adapter: update session
- [ ] Internal adapter: delete session
- [ ] Internal adapter: delete accounts
- [ ] Internal adapter: delete account
- [ ] Internal adapter: delete sessions
- [ ] Internal adapter: find OAuth user
- [ ] Internal adapter: find user by email
- [ ] Internal adapter: find user by ID
- [ ] Internal adapter: link account
- [ ] Internal adapter: update user
- [ ] Internal adapter: update user by email
- [ ] Internal adapter: update password
- [ ] Internal adapter: find accounts
- [ ] Internal adapter: find account
- [ ] Internal adapter: find account by provider ID
- [ ] Internal adapter: find accounts by user ID
- [ ] Internal adapter: update account
- [ ] Internal adapter: create verification value
- [ ] Internal adapter: find verification value
- [ ] Internal adapter: delete verification by identifier
- [ ] Internal adapter: update verification by identifier

## Database Hooks

- [ ] User create before hook
- [ ] User create after hook
- [ ] User update before hook
- [ ] User update after hook
- [ ] User delete before hook
- [ ] User delete after hook
- [ ] Session create before hook
- [ ] Session create after hook
- [ ] Session update before hook
- [ ] Session update after hook
- [ ] Session delete before hook
- [ ] Session delete after hook
- [ ] Account create before hook
- [ ] Account create after hook
- [ ] Account update before hook
- [ ] Account update after hook
- [ ] Account delete before hook
- [ ] Account delete after hook
- [ ] Verification create before hook
- [ ] Verification create after hook
- [ ] Verification update before hook
- [ ] Verification update after hook
- [ ] Verification delete before hook
- [ ] Verification delete after hook
- [ ] Hook return handling: continue, replace data, cancel with `false`
- [ ] Hook context may be endpoint context or null
- [ ] After-transaction hook queueing

## Database Schemas

- [x] Shared core fields: `id`, `createdAt`, `updatedAt`
- [x] User schema: `email`, `emailVerified`, `name`, `image`
- [x] User email normalization to lowercase
- [x] Account schema: `providerId`, `accountId`, `userId`
- [x] Account token fields: `accessToken`, `refreshToken`, `idToken`
- [x] Account token expiry fields: `accessTokenExpiresAt`, `refreshTokenExpiresAt`
- [x] Account scope field
- [x] Account password field for credential provider
- [x] Session schema: `userId`, `expiresAt`, `token`, `ipAddress`, `userAgent`
- [x] Verification schema: `identifier`, `value`, `expiresAt`
- [x] Rate-limit schema: `key`, `count`, `lastRequest`
- [ ] Schema support for plugin-provided fields
- [x] Schema support for option-provided additional fields

## Auth Table Generation

- [ ] Merge plugin schemas into core table schemas
- [ ] Preserve plugin model names
- [x] User table generation
- [x] Session table generation
- [x] Account table generation
- [x] Verification table generation
- [x] Rate-limit table generation when storage is database
- [x] Custom model names per table
- [x] Custom field names per table
- [x] Additional fields per table
- [ ] Field defaults for created/updated timestamps
- [ ] `updatedAt` on-update behavior
- [x] User email unique/index/sortable behavior
- [x] Session token uniqueness
- [x] User/session/account foreign key reference behavior
- [x] Sensitive account fields marked non-returned
- [ ] Secondary-storage behavior: omit session table unless database session storage is forced
- [x] Secondary-storage behavior: omit verification table unless database verification storage is forced
- [ ] Table order metadata
- [ ] Upstream get-tables tests adapted

## DB Field And Adapter Contracts

- [x] Adapter factory config defaults are applied consistently
- [ ] Unsupported numeric IDs with `generateId = serial` and adapter `supportsNumericIds = false` returns a typed configuration error
- [ ] Adapter factory instance ID is unique enough for debug log isolation
- [ ] Adapter debug logs support global enablement
- [ ] Adapter debug logs support per-method filtering
- [ ] Adapter debug logs support conditional logging
- [ ] Adapter debug logs support in-memory capture for adapter test failures
- [x] Model name types: user, account, session, verification, rate-limit, plugin models
- [x] DB field types: string, number, boolean, date, JSON, arrays, enum-like literal arrays
- [ ] DB field flags: required, returned, input, unique, bigint, sortable, index
- [ ] DB field default value behavior
- [ ] DB field on-update behavior
- [ ] DB field input transform behavior
- [ ] DB field output transform behavior
- [x] DB field references and delete actions
- [ ] DB field validators
- [ ] Secondary storage contract
- [ ] Adapter debug log option
- [x] Adapter schema creation contract
- [ ] Adapter factory config: plural names
- [x] Adapter factory config: adapter ID/name
- [x] Adapter factory config: numeric IDs, UUIDs, JSON, dates, booleans, arrays
- [x] Adapter factory config: transactions
- [x] Adapter factory config: ID generation disabling
- [ ] Adapter factory config: key input/output mapping
- [ ] Adapter factory config: custom input/output transforms
- [ ] Adapter factory config: custom ID generator
- [ ] Adapter factory config: disabling input/output/join transforms
- [ ] Where operators: eq, ne, lt, lte, gt, gte, in, not_in, contains, starts_with, ends_with
- [x] Where connector behavior: AND and OR
- [x] Where string sensitivity mode
- [ ] Where `in` operator rejects non-array values
- [x] Where transform maps custom field names
- [ ] Where transform converts serial IDs and ID references to numbers
- [x] Where transform converts Date values for adapters without date support
- [ ] Where transform converts string booleans to booleans
- [x] Where transform converts booleans to numeric values for adapters without boolean support
- [ ] Where transform converts numeric strings and numeric string arrays
- [x] Where transform serializes JSON values for adapters without JSON support
- [ ] Where transform applies custom input transform
- [x] Join option contract
- [x] Join config contract
- [x] Join transform detects forward foreign keys from joined model to base model
- [x] Join transform detects backward foreign keys from base model to joined model
- [x] Join transform errors when no foreign key exists
- [ ] Join transform errors when multiple foreign keys exist
- [x] Join transform adds required select field when select is constrained
- [x] Join transform chooses one-to-one relation for unique/id joins
- [x] Join transform chooses one-to-many relation otherwise
- [x] Join transform applies default findMany limit
- [x] Join transform applies explicit join limit
- [ ] Native joins are passed through only when experimental joins are enabled
- [ ] Fallback joins query joined data separately when native joins are unavailable
- [ ] Fallback joins return null for one-to-one missing values
- [ ] Fallback joins return empty array for one-to-many missing values
- [ ] DB adapter operations: create, findOne, findMany, count, update, updateMany, delete, deleteMany, transaction, createSchema
- [ ] Custom adapter operations
- [x] Adapter instance contract
- [x] Default model name resolver
- [x] Custom/plural model name resolver
- [x] Default field name resolver
- [x] Custom field name resolver
- [x] Field attributes resolver and field-not-found error
- [x] ID field resolver
- [x] ID generation disabled behavior
- [x] Serial/numeric ID behavior
- [x] UUID generation behavior
- [ ] DB-native UUID behavior
- [ ] Custom `generateId` priority over UUID/custom adapter generator
- [ ] Adapter custom ID generator fallback
- [ ] Default random ID fallback
- [x] `forceAllowId` behavior
- [ ] Create with user-provided `id` warns and ignores ID unless `forceAllowId` is set
- [ ] Invalid UUID warning behavior
- [x] ID input/output transforms
- [ ] Apply defaults on create
- [ ] Apply on-update values on update
- [ ] Input transform converts date strings into Date values before storage transforms
- [x] Input transform stringifies JSON when adapter lacks JSON support
- [x] Input transform stringifies arrays when adapter lacks array support
- [x] Input transform serializes dates when adapter lacks date support
- [x] Input transform serializes booleans when adapter lacks boolean support
- [ ] Input transform applies field-level transform before adapter-level custom transform
- [ ] Output transform maps custom output keys
- [ ] Output transform honors selected fields
- [ ] Output transform always returns IDs and ID references as strings
- [ ] Output transform parses JSON strings when adapter lacks JSON support
- [ ] Output transform parses array strings when adapter lacks array support
- [ ] Output transform parses date strings when adapter lacks date support
- [ ] Output transform parses numeric booleans when adapter lacks boolean support
- [ ] Output transform applies field-level output transform before adapter-level custom transform
- [ ] Operation wrappers create OpenTelemetry DB spans for every adapter method
- [ ] Operation wrappers log unsafe input, parsed input, DB result and parsed result where applicable
- [ ] `findMany` default limit uses `advanced.database.defaultFindManyLimit` or 100
- [x] `findMany` supports sort, offset, select and join
- [ ] `createSchema` removes session table when secondary storage is enabled and database session storage is not forced
- [ ] Adapter exposes resolved adapter config in options
- [ ] Adapter exposes adapter test debug log helper only in adapter-test mode
- [ ] Deep merge utility
- [x] Upstream get-id-field tests adapted

## API Endpoint Helpers

- [ ] APIError response-header attachment helper
- [ ] Options middleware that injects auth context typing/runtime placeholder
- [ ] Auth middleware factory with returned/responseHeaders metadata
- [x] Auth endpoint creation with path overload behavior translated to Rust route builder semantics
- [x] All core endpoints in future implementation should use the Rust equivalent of `createAuthEndpoint`
- [x] Endpoint options must be forwarded intact, including method, body/query/headers schemas, metadata, OpenAPI data, operation ID and middleware list when present
- [x] Existing middleware preservation when wrapping endpoints
- [x] Endpoint execution inside auth endpoint context
- [ ] APIError header preservation when endpoint throws
- [x] Do not bypass auth endpoint context when adding plugin or core endpoints

## Async Context

- [ ] Server async local storage loader
- [ ] Warning/error behavior when server async local storage is unavailable
- [ ] Pure async local storage polyfill
- [ ] Global Better Auth context storage using a process-global key equivalent
- [ ] Version tracking in global context
- [ ] Epoch increment when version changes
- [ ] Endpoint context storage
- [ ] Get current endpoint auth context
- [ ] Run callback with endpoint auth context
- [x] Request state storage
- [x] Check if request state exists
- [x] Get current request state or throw outside context
- [x] Run callback with request state
- [x] Define request-scoped lazy state
- [x] Request state get/set operations
- [x] Concurrent request-state isolation tests adapted
- [ ] Nested async request-state tests adapted
- [ ] Adapter context storage
- [ ] Get current adapter with fallback
- [ ] Run callback with adapter context
- [ ] Run callback with transaction adapter context
- [ ] Queue after-transaction hooks
- [ ] Execute queued hooks after success or error
- [ ] Immediate hook execution outside transaction context

## Errors

- [ ] BetterAuthError type with stable name/message semantics
- [ ] APIError wrapper
- [ ] APIError `fromStatus`
- [ ] APIError `from`
- [ ] Base error codes registry
- [ ] Error code definition helper
- [ ] Upper-snake-case validation equivalent for plugin/base error IDs
- [ ] Base errors: user/session/account/token/password/email/provider/origin/URL/validation/CSRF/fresh-session coverage

## OAuth2 Core

- [ ] OAuth2 token model
- [ ] OAuth2 user info model
- [ ] OAuth provider trait/contract
- [ ] Provider options contract
- [ ] Primary client ID selection
- [ ] OAuth token response normalization
- [ ] Preserve raw token response
- [ ] PKCE code challenge generation
- [ ] Authorization URL builder
- [ ] Authorization URL parameters: response type, client ID, state, scope, redirect URI
- [ ] Authorization URL optional parameters: duration, display, login hint, prompt, hosted domain, access type, response mode
- [ ] Authorization URL PKCE parameters
- [ ] Authorization URL claims parameter
- [ ] Authorization URL additional params
- [ ] Authorization URL custom scope joiner
- [ ] Authorization code request builder
- [ ] Authorization code validation request
- [ ] Authorization code Basic auth
- [ ] Authorization code post/body auth
- [ ] Authorization code device ID
- [ ] Authorization code additional params
- [ ] Authorization code resource parameter
- [ ] Authorization code token exchange
- [ ] Token validation against remote JWKS
- [ ] Refresh token request builder
- [ ] Refresh token Basic auth
- [ ] Refresh token post/body auth
- [ ] Refresh token resource parameter
- [ ] Refresh token extra params
- [ ] Refresh token exchange
- [ ] Access token expiry calculation
- [ ] Refresh token expiry calculation
- [ ] Client credentials request builder
- [ ] Client credentials Basic auth
- [ ] Client credentials post/body auth
- [ ] Client credentials resource parameter
- [ ] Client credentials token exchange
- [ ] JWS access token verification
- [ ] JWKS fetching and cache behavior
- [ ] Missing `kid` error behavior
- [ ] Remote introspection verification
- [ ] Forced remote verification
- [ ] JWT expired and invalid error mapping
- [ ] Opaque token fallback to remote verification
- [ ] Scope verification and forbidden error behavior
- [ ] Audience verification
- [ ] Issuer verification
- [ ] Upstream refresh access token tests adapted
- [ ] Upstream validate token tests adapted

## Social Providers

Upstream has provider implementation files but no dedicated social-provider test files in `packages/core`. For porting, each provider should still get implementation coverage plus at least provider-shape/user-mapping tests when it affects server behavior.

- [ ] Social provider registry map
- [x] Social provider list
- [ ] Social provider enum/string validation behavior
- [ ] Social provider options map with `enabled`
- [ ] Apple provider implementation
- [ ] Apple provider tests
- [ ] Atlassian provider implementation
- [ ] Atlassian provider tests
- [ ] Cognito provider implementation
- [ ] Cognito provider tests
- [ ] Discord provider implementation
- [ ] Discord provider tests
- [ ] Dropbox provider implementation
- [ ] Dropbox provider tests
- [ ] Facebook provider implementation
- [ ] Facebook provider tests
- [ ] Figma provider implementation
- [ ] Figma provider tests
- [ ] GitHub provider implementation
- [ ] GitHub provider tests
- [ ] GitLab provider implementation
- [ ] GitLab provider tests
- [ ] Google provider implementation
- [ ] Google provider tests
- [ ] Hugging Face provider implementation
- [ ] Hugging Face provider tests
- [ ] Kakao provider implementation
- [ ] Kakao provider tests
- [ ] Kick provider implementation
- [ ] Kick provider tests
- [ ] Line provider implementation
- [ ] Line provider tests
- [ ] Linear provider implementation
- [ ] Linear provider tests
- [ ] LinkedIn provider implementation
- [ ] LinkedIn provider tests
- [ ] Microsoft Entra ID provider implementation
- [ ] Microsoft Entra ID provider tests
- [ ] Naver provider implementation
- [ ] Naver provider tests
- [ ] Notion provider implementation
- [ ] Notion provider tests
- [ ] Paybin provider implementation
- [ ] Paybin provider tests
- [ ] PayPal provider implementation
- [ ] PayPal provider tests
- [ ] Polar provider implementation
- [ ] Polar provider tests
- [ ] Railway provider implementation
- [ ] Railway provider tests
- [ ] Reddit provider implementation
- [ ] Reddit provider tests
- [ ] Roblox provider implementation
- [ ] Roblox provider tests
- [ ] Salesforce provider implementation
- [ ] Salesforce provider tests
- [ ] Slack provider implementation
- [ ] Slack provider tests
- [ ] Spotify provider implementation
- [ ] Spotify provider tests
- [ ] TikTok provider implementation
- [ ] TikTok provider tests
- [ ] Twitch provider implementation
- [ ] Twitch provider tests
- [ ] Twitter/X provider implementation
- [ ] Twitter/X provider tests
- [ ] Vercel provider implementation
- [ ] Vercel provider tests
- [ ] VK provider implementation
- [ ] VK provider tests
- [ ] WeChat provider implementation
- [ ] WeChat provider tests
- [ ] Zoom provider implementation
- [ ] Zoom provider tests

## Social Provider Shared Behavior

- [ ] Default scopes per provider
- [ ] `disableDefaultScope` behavior
- [ ] Additional configured scopes behavior
- [ ] Runtime scopes passed to auth URL behavior
- [ ] Custom authorization endpoint override where supported
- [ ] Redirect URI override behavior
- [ ] PKCE support where provider uses `codeVerifier`
- [ ] Basic vs post token authentication per provider
- [ ] Provider-specific token endpoint behavior
- [ ] Provider-specific user info endpoint behavior
- [ ] Provider-specific profile model
- [ ] Provider profile to core user mapping
- [ ] `mapProfileToUser` override behavior
- [ ] `getUserInfo` override behavior
- [ ] `refreshAccessToken` override behavior
- [ ] Default refresh access token behavior where provider supports it
- [ ] ID token verification override behavior
- [ ] Default ID token verification behavior where provider supports it
- [ ] Audience validation for providers with ID tokens
- [ ] Issuer validation for providers with ID tokens
- [ ] Nonce validation where provider supports ID token verification
- [ ] Public key/JWKS fetch helpers for Google/Cognito and equivalent providers
- [ ] Provider-specific sandbox/tenant/domain options
- [ ] Providers with non-standard token/profile responses
- [ ] Providers without refresh token support
- [ ] Providers without ID token support
- [ ] Providers that require client ID and secret return clear typed errors
- [ ] Providers that support public clients do not require client secret unnecessarily
- [ ] Provider-specific Basic auth behavior
- [ ] Provider-specific post/body auth behavior
- [ ] Provider-specific custom query params such as config IDs, token access type, hosted domain, prompt, login hint, claims and resources
- [ ] Provider-specific user profile fetch methods: GET, POST form, GraphQL, token-derived ID token profile
- [ ] Provider-specific image/photo mapping, including Microsoft Graph photo data URL behavior
- [ ] Provider-specific environment/tenant/domain support: sandbox/live, sandbox/production, issuer, tenant ID, authority, domain/region/user pool
- [ ] Provider-specific manual auth URL construction where upstream does not use the shared builder
- [ ] Provider-specific token response parsing when upstream bypasses shared token helper
- [ ] Provider public key helpers: Apple, Google, Cognito, Microsoft
- [ ] Facebook remote JWKS verification path
- [ ] Line remote token verification endpoint path
- [ ] PayPal lightweight decode/nonce verification behavior
- [ ] Twitch ID-token-only profile extraction behavior
- [ ] Paybin ID-token profile extraction behavior

## Env And Logger

- [ ] Env object abstraction
- [ ] Node/test/development/production flags
- [ ] Env string lookup with fallback
- [ ] Boolean env lookup
- [ ] Frozen ENV helper object
- [ ] Color depth detection
- [ ] TTY colors constants
- [x] Log levels: debug, info, success, warn, error
- [x] Log-level publish ordering
- [ ] Logger options: disabled, disable colors, level, custom handler
- [ ] Formatted console logging
- [x] Custom handler logging with success mapped to info
- [x] Default logger
- [x] Upstream logger tests adapted

## Instrumentation

- [ ] OpenTelemetry semantic attributes export
- [ ] Better Auth operation ID attribute
- [ ] Better Auth hook type attribute
- [ ] Better Auth context attribute
- [ ] Lazy OpenTelemetry API loading
- [ ] Noop OpenTelemetry API fallback
- [ ] Noop span mutators
- [ ] Noop tracer `startActiveSpan` overload behavior translated to Rust API shape
- [ ] `withSpan` for synchronous operations
- [ ] `withSpan` for async operations
- [ ] Span success ending
- [ ] Span error recording
- [ ] Redirect APIError treated as OK with response status attribute
- [ ] Instrumentation scope name/version
- [ ] Pure instrumentation entry with same public surface and no OpenTelemetry runtime dependency
- [ ] Upstream instrumentation tests adapted
- [ ] Upstream noop instrumentation tests adapted
- [ ] Upstream pure instrumentation tests adapted

## Utilities

- [x] Random ID generation
- [x] Output field filtering for `returned: false`
- [ ] Deprecation wrapper warns once
- [ ] Deprecation wrapper preserves arguments, return value and receiver
- [ ] Safe JSON parse
- [ ] ISO date revival in parsed JSON
- [ ] String capitalization helper
- [x] Pathname normalization
- [ ] APIError type guard
- [x] Browser fetch metadata detection
- [ ] Bounded concurrent mapper
- [ ] Bounded mapper preserves input order
- [ ] Bounded mapper clamps concurrency
- [ ] Bounded mapper supports sync and async mapping
- [ ] Bounded mapper fails fast
- [ ] Bounded mapper abort signal behavior
- [ ] Upstream async utility tests adapted
- [ ] Upstream deprecate tests adapted
- [x] Upstream fetch metadata tests adapted

## IP And Host Security Utilities

- [x] IP validity check
- [x] IPv4 normalization
- [x] IPv6 expansion and lowercase canonicalization
- [x] IPv4-mapped IPv6 conversion
- [x] IPv6 subnet normalization
- [x] Rate-limit key creation with separator
- [x] Rate-limit key collision prevention
- [x] Host classification model
- [x] Host input normalization: brackets, ports, zone IDs, trailing dots, case, whitespace
- [x] IPv4 special range classification
- [ ] IPv6 special range classification
- [ ] IPv4-mapped IPv6 host classification
- [ ] 6to4 tunnel classification
- [ ] NAT64 classification
- [ ] Teredo classification
- [x] FQDN localhost classification
- [x] Cloud metadata FQDN classification
- [x] Strict loopback IP check
- [x] Permissive loopback host check
- [x] Public routable host/SSRF gate
- [x] Upstream IP tests adapted
- [x] Upstream host classification tests adapted

## Test Inventory From Upstream Core

- [x] `src/context/request-state.test.ts`
- [x] `src/db/adapter/get-id-field.test.ts`
- [ ] `src/db/test/get-tables.test.ts`
- [x] `src/env/logger.test.ts`
- [ ] `src/instrumentation/instrumentation.test.ts`
- [ ] `src/instrumentation/noop.test.ts`
- [ ] `src/instrumentation/pure.test.ts`
- [ ] `src/oauth2/refresh-access-token.test.ts`
- [ ] `src/oauth2/validate-token.test.ts`
- [ ] `src/utils/async.test.ts`
- [ ] `src/utils/deprecate.test.ts`
- [x] `src/utils/fetch-metadata.test.ts`
- [x] `src/utils/host.test.ts`
- [x] `src/utils/ip.test.ts`

## Additional Recommended Coverage

- [ ] Add provider tests even where upstream lacks them, using mocked HTTP/JWKS responses
- [ ] Add tests that every future core endpoint goes through the `createAuthEndpoint` equivalent and preserves OpenAPI/operation metadata
- [ ] Add adapter factory tests for JSON/date/boolean/array transforms across backend capability combinations
- [ ] Add adapter factory tests for native joins and fallback joins
- [ ] Add tests for `createSchema` with secondary storage and forced DB session/verification storage
- [ ] Add tests for dependency boundary injection: HTTP client, clock/time, random ID generator, JWKS fetcher
- [ ] Add stronger SSRF tests around DNS resolution and redirects if the Rust implementation performs outbound fetches to user-controlled hosts
- [ ] Add tests for encrypted OAuth token storage when account token encryption is implemented
- [ ] Add tests for background task handler failures and non-blocking behavior

## Improvements Allowed Over Upstream

- [x] Use typed Rust errors instead of stringly TS errors when behavior is equivalent
- [ ] Use explicit dependency traits for HTTP, clock, random, crypto/JWKS and storage to make security tests deterministic
- [ ] Strengthen SSRF protection beyond upstream syntactic host checks by validating resolved IPs and redirect targets when doing server-side fetches
- [x] Prefer small Rust modules over upstream large files, especially DB adapter factory and provider-specific logic
- [x] Preserve upstream behavior while improving validation at API boundaries
- [ ] Keep optional integrations behind feature flags where practical

## Implementation Order Recommendation

- [ ] Types/contracts first
- [ ] Errors and utilities
- [ ] DB schemas and table generation
- [ ] DB adapter contracts and transform behavior
- [ ] Async context and request state
- [ ] API endpoint helper layer
- [ ] OAuth2 primitives
- [ ] Social provider registry and providers
- [ ] Env/logger
- [ ] Instrumentation
- [ ] Cross-module tests and security regression tests

## Self-Review

- [ ] Confirm checklist is based only on upstream `packages/core`
- [ ] Confirm no current OpenAuth implementation status is encoded
- [ ] Confirm client-only `plugin-client.ts` is excluded
- [ ] Confirm social providers are listed individually
- [ ] Confirm upstream tests are listed at file-level granularity
- [ ] Confirm security-sensitive behavior has checklist coverage
- [ ] Confirm dependency-provided functionality has checklist coverage
- [ ] Confirm endpoint creation/OpenAPI metadata preservation has checklist coverage
- [ ] Confirm modularization requirement is documented
