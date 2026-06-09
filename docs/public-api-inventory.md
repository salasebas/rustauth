# OpenAuth public API inventory

Inventory of public APIs across workspace crates that a third party can implement or integrate against. Snapshot of the repo layout; not a quality judgment.

## Quick map

```text
openauth                    ← umbrella (re-exports most crates)
├── openauth-core           ← framework, traits, DB, plugins, HTTP API
├── openauth-axum           ← Axum mount
├── openauth-oauth          ← OAuth client primitives
├── openauth-social-providers
├── openauth-plugins
├── openauth-oauth-provider ← authorization server (separate crate)
├── openauth-sso / saml / oidc / scim / passkey / stripe / i18n / telemetry
└── adapters: sqlx, redis, fred, deadpool-postgres, tokio-postgres
```

---

## 1. App dev — mount OpenAuth

### `openauth` (`crates/openauth/src/lib.rs`)

| API | Location |
|-----|----------|
| `OpenAuth`, `OpenAuthBuilder` | `crates/openauth/src/auth.rs` |
| `open_auth`, `open_auth_with_adapter`, `open_auth_with_endpoints`, `*_async` | same |
| Re-export of `openauth_core::*` | `lib.rs` |
| Optional re-exports: `plugins`, `sso`, `scim`, `passkey`, `stripe`, `sqlx`, `i18n`, `telemetry`, etc. | `lib.rs` (features) |

**Builder methods** (`.secret()`, `.base_url()`, `.adapter()`, `.social_provider()`, `.plugin()`, …): `crates/openauth/src/auth.rs`

### `openauth-axum` (`crates/openauth-axum/src/lib.rs`)

| API | Location |
|-----|----------|
| `router`, `router_with_options` | `router.rs` |
| `routes`, `routes_with_options` | same |
| `handle`, `handle_ref`, `handle_*_with_options` | same |
| `OpenAuthAxumExt` (trait) | `router.rs` |
| `OpenAuthAxumOptions` | `options.rs` |

---

## 2. Framework core — `openauth-core`

Public modules: `api`, `auth`, `context`, `cookies`, `crypto`, `db`, `env`, `error`, `options`, `plugin`, `rate_limit`, `session`, `user`, `verification`, `oauth`* , `social_providers`*

\* features `oauth` / `social-providers`

### Implementable traits

| Trait | Purpose | Location |
|-------|---------|----------|
| `DbAdapter` | persistence | `db/adapter/traits.rs` |
| `Connector`, `TransactionAdapter` | SQL transactions | `db/adapter/traits.rs` |
| `SqlExecutor`, `SqlRowReader` | custom SQL adapters | `db/sql/executor.rs` |
| `RateLimitStore`, `RateLimitStorage`, `RateLimitRuleProvider` | rate limiting | `options/rate_limit.rs` |
| `SecondaryStorage` | secondary KV | `options/storage.rs` |
| `SocialOAuthProvider`* | social OAuth | re-export from `openauth-oauth` |
| `SendVerificationEmail`, `BeforeEmailVerification`, `AfterEmailVerification` | email verification | `options/email_verification.rs` |
| `SendResetPassword`, `OnPasswordReset` | password reset | `options/password.rs` |
| `SendChangeEmailConfirmation`, `BeforeDeleteUser`, `AfterDeleteUser`, `SendDeleteAccountVerification` | account lifecycle | `options/user.rs` |
| `OnExistingUserSignUp` | sign-up | `options/email_password.rs` |
| `TrustedOriginsProvider` | CORS / origins | `options/origins.rs` |
| `TrustedProvidersProvider`, `TrustedProvidersRequestProvider` | account linking | `options/account.rs` |
| `GlobalBeforeHook`, `GlobalAfterHook` | global hooks | `options/hooks.rs` |
| `InitDatabaseBeforeHook`, `InitDatabaseAfterHook` | DB init hooks | `options/init_database_hooks.rs` |
| `BackgroundTaskRunner` | background tasks | `options/advanced.rs` |
| `OnApiErrorHandler` | API errors | `options/api_error.rs` |
| `JweSecretSource`, `SecretSource` | crypto | `crypto/jwe_secret.rs`, `crypto/symmetric.rs` |
| `AdditionalField` | extra fields | `api/additional_fields.rs` |
| `ContextTelemetryPublisher` (type alias) | context telemetry | `context.rs` |

### Plugin system (`plugin.rs`)

| API | Location |
|-----|----------|
| `AuthPlugin` + `.with_endpoint()`, `.with_init()`, `.with_schema()`, `.with_rate_limit()`, `.with_*_hook()`, `.with_database_hook()`, `.with_social_provider()`*, `.with_password_validator()` | `plugin.rs` |
| `PluginInitOutput`, `PluginSchemaContribution`, `PluginRateLimitRule`, `PluginErrorCode` | `plugin/*.rs` |
| `PluginDatabaseHook`, `PluginMigration`, sync/async hooks | `plugin/db.rs`, `plugin/hooks.rs` |
| `PluginPasswordValidator` | `plugin/password.rs` |
| `PluginEndpoint` (= `AsyncAuthEndpoint`) | `plugin/endpoint.rs` |

### HTTP / custom endpoints (`api.rs`)

| API | Location |
|-----|----------|
| `create_auth_endpoint`, `core_auth_async_endpoints`, `core_endpoints` | `api/endpoint.rs`, `api/router.rs` |
| `AuthRouter`, `AuthEndpoint`, `AsyncAuthEndpoint` | `api/endpoint.rs`, `api/router.rs` |
| `AuthEndpointOptions`, `EndpointMiddleware`, `EndpointInfo` | `api/endpoint.rs` |
| `ApiRequest`, `ApiResponse`, `parse_request_body` | `api/endpoint.rs`, `api/body.rs` |
| `BodySchema`, `BodyField`, `OpenApiOperation` | `api/schema.rs`, `api/openapi.rs` |
| `ApiErrorCode`, `ApiErrorResponse` | `api/error.rs` |

### DB / schema (`db/mod.rs`)

| API | Location |
|-----|----------|
| `MemoryAdapter`, `HookedAdapter`, `JoinAdapter`, `SchemaAdapter` | `db/memory.rs`, `db/hooks.rs`, `db/factory.rs` |
| `User`, `Session`, `Account`, `Verification`, `RateLimit` | `db/models.rs` |
| `auth_schema`, `DbSchema`, `DbTable`, `DbField`, `RateLimitStorage` | `db/schema.rs` |
| `FindMany`, `Create`, `Update`, `Where`, … | `db/adapter/traits.rs` |
| SQL: `SqlDialect`, `SqlStatement`, migrations, rate-limit SQL | `db/sql/*` |

### Options (`options/`)

`OpenAuthOptions`, `SessionOptions`, `EmailPasswordOptions`, `AccountOptions`, `CookieConfig`, `RateLimitOptions`, `HybridRateLimitOptions`, `TelemetryOptions`, `AdvancedOptions`, …

### Direct auth flows (no HTTP)

| API | Location |
|-----|----------|
| `EmailPasswordAuth`, `SignInInput`, `SignUpInput` | `auth/email_password.rs` |
| `SessionAuth`, `GetSessionInput` | `auth/session.rs` |
| `DbUserStore`, `DbSessionStore`, `DbVerificationStore` | `user/`, `session/`, `verification/` |
| `generate_oauth_state`, `OAuthStateInput` | `auth/oauth/state.rs` |

### In-memory rate limit

`GovernorMemoryRateLimitStore`, `HybridRateLimitStore`, `LegacyRateLimitStorageAdapter` → `rate_limit.rs`

### Context

`create_auth_context`, `create_auth_context_with_adapter`, `AuthContext`, `AuthEnvironment` → `context/builder.rs`, `context.rs`

---

## 3. OAuth client — `openauth-oauth`

Entry: `crates/openauth-oauth/src/oauth2/mod.rs`

### Traits

| Trait | Location |
|-------|----------|
| `SocialOAuthProvider` | `oauth2/provider.rs` |
| `OAuthProviderContract` | same |

### Functions and types

| Group | Symbols |
|-------|---------|
| Authorization URL | `create_authorization_url`, `AuthorizationUrlRequest::try_new`, `validate_authorization_url_invariants` |
| Auth code | `create_authorization_code_request`, `validate_authorization_code`, `validate_authorization_code_with_client`, `AuthorizationCodeRequest` |
| Refresh | `create_refresh_access_token_request`, `refresh_access_token`, `RefreshAccessTokenRequest` |
| Client credentials | `client_credentials_token`, `ClientCredentialsTokenRequest` |
| Tokens | `get_oauth2_tokens`, `OAuth2Tokens`, `OAuth2UserInfo`, `ProviderOptions`, `ClientId` |
| PKCE | `generate_code_challenge`, `validate_code_verifier` |
| HTTP | `OAuthHttpClient`, `OAuthHttpClientConfig` |
| SSRF | `SsrfGuardResolver`, `ssrf_guarded_client_builder`, `is_blocked_ip` |
| Newtypes | `AuthorizationEndpoint`, `TokenEndpoint`, `RedirectUri`, `ClientSecret` |
| JOSE (feature `jose`) | `verify_jws_with_jwks`, `validate_token`, `verify_access_token`, `OAuthJwksCacheConfig`, … |

### Request structs

`SocialAuthorizationUrlRequest`, `SocialAuthorizationCodeRequest`, `SocialIdTokenRequest`, `OAuthFormRequest`, `ClientAuthentication`, `ClientTokenRequest`

---

## 4. Social providers — `openauth-social-providers`

**Primary audience:** app dev (register providers on `OpenAuthOptions`).

### Application API (`providers`, `config`)

| API | Purpose |
|-----|---------|
| `providers::{apple, atlassian, cognito, discord, …}` | Factories taking `SocialProviderConfig` |
| `SocialProviderConfig::new(client_id, client_secret)` | Short-form credentials |
| `SocialProviderConfig::builder()` → `.client_id()` / `.client_secret()` / … → `.build()?` | Staged setup with validation |
| `ProviderId` | Stable provider id constants (`ProviderId::GITHUB`, …) |
| `CognitoPoolConfig` | Cognito domain / region / user pool (with `providers::cognito`) |
| `PROVIDER_IDS`, `VERSION` | Registry metadata |

### Advanced API (`advanced::*`)

Low-level per-provider modules (request structs, profile types, endpoint constants,
`map_*_user_info`, provider-specific `*Options`). Shared HTTP:
`advanced::http::{ProviderHttpClient, ValidationHttpClient, shared_client}`.

**Internal:** `runtime/*` (`SocialOAuthProvider` macro wiring to core).

### `providers` catalog

| Provider | Factory | Advanced module |
|----------|---------|-----------------|
| Apple | `providers::apple()` | `advanced::apple` |
| Atlassian | `providers::atlassian()` | `advanced::atlassian` |
| Cognito | `providers::cognito(config, pool)?` | `advanced::cognito` |
| Discord | `providers::discord()` | `advanced::discord` |
| Dropbox | `providers::dropbox()` | `advanced::dropbox` |
| Facebook | `providers::facebook()` | `advanced::facebook` |
| Figma | `providers::figma()` | `advanced::figma` |
| GitHub | `providers::github()` | `advanced::github` |
| GitLab | `providers::gitlab()` | `advanced::gitlab` |
| Google | `providers::google()` | `advanced::google` |
| Hugging Face | `providers::huggingface()` | `advanced::huggingface` |
| Kakao | `providers::kakao()` | `advanced::kakao` |
| Kick | `providers::kick()` | `advanced::kick` |
| Line | `providers::line()` | `advanced::line` |
| Linear | `providers::linear()` | `advanced::linear` |
| LinkedIn | `providers::linkedin()` | `advanced::linkedin` |
| Microsoft Entra | `providers::microsoft_entra_id()` | `advanced::microsoft_entra_id` |
| Naver | `providers::naver()` | `advanced::naver` |
| Notion | `providers::notion()` | `advanced::notion` |
| Paybin | `providers::paybin()` | `advanced::paybin` |
| PayPal | `providers::paypal()` | `advanced::paypal` |
| Polar | `providers::polar()` | `advanced::polar` |
| Railway | `providers::railway()` | `advanced::railway` |
| Reddit | `providers::reddit()` | `advanced::reddit` |
| Roblox | `providers::roblox()` | `advanced::roblox` |
| Salesforce | `providers::salesforce()` | `advanced::salesforce` |
| Slack | `providers::slack()` | `advanced::slack` |
| Spotify | `providers::spotify()` | `advanced::spotify` |
| TikTok | `providers::tiktok()` | `advanced::tiktok` |
| Twitch | `providers::twitch()` | `advanced::twitch` |
| Twitter/X | `providers::twitter()` | `advanced::twitter` |
| Vercel | `providers::vercel()` | `advanced::vercel` |
| VK | `providers::vk()` | `advanced::vk` |
| WeChat | `providers::wechat()` | `advanced::wechat` |
| Zoom | `providers::zoom()` | `advanced::zoom` |

---

## 5. Official plugins — `openauth-plugins`

Public modules: `lib.rs` (25 modules) + `PLUGIN_IDS`

### Plugin factories → `AuthPlugin`

| Plugin | Factory | File |
|--------|---------|------|
| Admin | `admin()` | `admin/mod.rs` |
| Anonymous | `anonymous()` | `anonymous/mod.rs` |
| API Key | `api_key()`, `api_key_with_options()`, `api_key_with_build()`, `api_key_with_configurations*()` | `api_key/mod.rs` |
| Bearer | `bearer()`, `bearer_with_options()` | `bearer/mod.rs` |
| Captcha | `captcha()` | `captcha/mod.rs` |
| Custom session | `custom_session()`, `custom_session_with_*()` | `custom_session/mod.rs` |
| Device authorization | `device_authorization()`, `device_authorization_with_options()` | `device_authorization/mod.rs` |
| Email OTP | `email_otp()` | `email_otp/mod.rs` |
| Generic OAuth | `generic_oauth()` | `generic_oauth/mod.rs` |
| Have I Been Pwned | `have_i_been_pwned()`, `have_i_been_pwned_with_options()`, `have_i_been_pwned_with_checker()` | `haveibeenpwned/plugin.rs` |
| JWT | `jwt()`, `jwt_with_options()` | `jwt/mod.rs` |
| Last login method | `last_login_method()` | `last_login_method/mod.rs` |
| Magic link | `magic_link()` | `magic_link/mod.rs` |
| Multi-session | `multi_session()`, `multi_session_with_config()` | `multi_session/mod.rs` |
| OAuth proxy | `oauth_proxy()`, `oauth_proxy_default()` | `oauth_proxy/mod.rs` |
| One Tap | `one_tap()` | `one_tap/mod.rs` |
| One-time token | `one_time_token()`, `one_time_token_with_options()` | `one_time_token/mod.rs` |
| OpenAPI | `open_api()` | `open_api/mod.rs` |
| Organization | `organization()`, `organization_with_options()`, `organization_options_from_context()` | `organization/mod.rs` |
| Phone number | `phone_number()` | `phone_number/mod.rs` |
| SIWE | `siwe()` | `siwe/mod.rs` |
| Two-factor | `two_factor()` | `two_factor/mod.rs` |
| Username | `username()`, `username_with_options()` | `username/mod.rs` |
| Additional fields | `additional_fields()` | `additional_fields/mod.rs` |

### `access` — RBAC helpers (not an `AuthPlugin`)

`create_access_control()`, `role()`, `statements()`, `request()`, `AccessControl`, `AccessRequest` → `access/`

### Generic OAuth presets (`generic_oauth/providers/`)

`auth0()`, `okta()`, `keycloak()`, `hubspot()`, `gumroad()`, `patreon()`, `slack()`, `line()`, `microsoft_entra_id()` + `*Options`

### Implementable plugin traits

| Trait | Module |
|-------|--------|
| `HaveIBeenPwnedChecker` | `haveibeenpwned/checker.rs` |
| `EmailOtpHasher`, `EmailOtpEncryptor`, `SendEmailOtp`, `EmailOtpGenerator` | `email_otp/types.rs` |

---

## 6. Enterprise / protocols

### `openauth-sso` — `sso()` → `AuthPlugin`

| API | Location |
|-----|----------|
| `sso()`, `SsoOptions`, `SsoProvider` | `lib.rs`, `options.rs` |
| OIDC: `OidcConfig`, `OidcOptions`, `OidcMapping` | `options.rs` |
| SAML: `SamlConfig`, `SamlOptions`, `SamlMapping` | `options.rs` |
| Resolvers: `ProvisionUserResolver`, `OrganizationRoleResolver`, `SsoAuditEventResolver`, `DnsTxtResolver` | `options.rs` |
| Store: `SsoProviderStore`, `CreateSsoProviderInput` | `store.rs` |
| Linking: `assign_organization_by_domain`, `validate_provider_domains`, `NormalizedSsoProfile` | `linking.rs` |
| Re-exports: `openauth_oidc`, `openauth_saml` (features) | `lib.rs` |

### `openauth-oidc` — OIDC RP client

`discover_oidc_config`, `OidcEndpointConfig` (trait), `OidcFlowOptions` (trait), `OidcConfig`, … → `lib.rs`

### `openauth-saml` — SAML SP

Modules: `assertions`, `authn_request`, `encryption`, `logout`, `metadata`, `security`, `signature`, `state`, `xml`; `SamlConfig`, `validate_saml_*`, algorithm types → `lib.rs`

### `openauth-scim` — `scim()` → `AuthPlugin`

| API | Location |
|-----|----------|
| `scim()`, `ScimOptions` | `lib.rs` |
| Hooks: `BeforeScimTokenGeneratedHook`, `AfterScimTokenGeneratedHook`, `ScimTokenStorage`, `ScimTokenTransform` | `options.rs` |
| `ScimProviderStore`, `ScimAuditEventResolver` | `store.rs`, `audit.rs` |
| `parse_filter`, `build_user_patch`, resources, metadata | `filters.rs`, `patch.rs`, `resources.rs` |

### `openauth-oauth-provider` — separate crate (not in umbrella `openauth`)

| API | Location |
|-----|----------|
| `oauth_provider()`, `oauth_provider_with_jwt()` | `lib.rs` |
| `OAuthProviderPlugin`, `OAuthProviderOptions` | `options.rs` |
| Custom resolvers: `ClientPrivilegesResolver`, `CustomAccessTokenClaimsResolver`, `CustomIdTokenClaimsResolver`, `RefreshTokenFormatter`, `RequestUriResolver`, `TokenHashResolver`, … | `options.rs` |
| Client / consent / token / metadata | various modules |
| MCP (feature): `McpAuthClient` | `mcp/client.rs` |

### `openauth-passkey` — `passkey()` → `AuthPlugin`

`passkey()`, `PasskeyOptions`, `PasskeyWebAuthnBackend` (trait), `RealPasskeyWebAuthnBackend`, `WebAuthnConfig` → `lib.rs`

---

## 7. Storage adapters

| Crate | Public types | Location |
|-------|--------------|----------|
| `openauth-sqlx` | `SqliteAdapter`, `PostgresAdapter`, `MySqlAdapter`, `*RateLimitStore`, `sqlite_pool_options` | `lib.rs` |
| `openauth-deadpool-postgres` | `DeadpoolPostgresAdapter`, `DeadpoolPostgresRateLimitStore`, migration types | `lib.rs` |
| `openauth-tokio-postgres` | `TokioPostgresAdapter`, `TokioPostgresConnection`, `TokioPostgresRateLimitStore`, `driver` | `lib.rs` |
| `openauth-redis` | `RedisRateLimitStore`, `RedisSecondaryStorage`, `RedisOpenAuthStores`, `RedisOpenAuthOptions` | `lib.rs` |
| `openauth-fred` | `FredRateLimitStore`, `FredSecondaryStorage`, `FredOpenAuthStores` | `lib.rs` |

All implement `openauth-core` traits: `DbAdapter`, `RateLimitStore`, and/or `SecondaryStorage`.

---

## 8. Other public crates

| Crate | Entry points | Location |
|-------|--------------|----------|
| `openauth-stripe` | `stripe()`, `StripeOptions`, `StripeClient`, `StripeTransport` (trait) | `lib.rs`, `stripe_api/` |
| `openauth-i18n` | `i18n()`, `I18nOptions`, `TranslationKey` (trait), `LocaleResolver` | `lib.rs` |
| `openauth-telemetry` | `create_telemetry()`, `TelemetryPublisher`, `TelemetryHttpTransport` (trait), `CustomTrackFn`, `get_telemetry_auth_config` | `lib.rs` |
| `openauth-cli` | `app`, `config`, `db`, `schema`, `workspace`, `plugins` (CLI tooling) | `lib.rs` |

---

## 9. Extension contracts (summary)

| Goal | Implement / use |
|------|-----------------|
| Persistence | `DbAdapter` (+ optional `SqlExecutor`) |
| Custom social OAuth | `SocialOAuthProvider` or new module in `openauth-social-providers` |
| Generic OAuth IdP | `generic_oauth()` / `GenericOAuthProvider` |
| Full feature (routes, schema, hooks) | `AuthPlugin::new(...).with_*()` or official plugin factory |
| Rate-limit backend | `RateLimitStore` / `RateLimitStorage` |
| Secondary KV | `SecondaryStorage` |
| Business hooks (email, account, …) | traits under `openauth-core::options` |
| Custom HTTP endpoints | `create_auth_endpoint` + `.plugin()` |
| Authorization server | `openauth-oauth-provider` |
| Enterprise SSO | `sso()` + `openauth-oidc` / `openauth-saml` |
| SCIM | `scim()` |
| Passkeys | `passkey()` + optional `PasskeyWebAuthnBackend` |
| Stripe | `stripe()` + optional `StripeTransport` |
| i18n | `i18n()` + `TranslationKey` |
| Telemetry | `TelemetryHttpTransport` / `CustomTrackFn` |
| HTTP framework | `openauth-axum` or `OpenAuth::handler_async` |

---

## 10. Umbrella `openauth` features

Optional crates via features: `plugins`, `sso`, `saml`, `scim`, `passkey`, `stripe`, `sqlx` (+ `sqlx-postgres` / `mysql` / `sqlite`), `telemetry`, `i18n`, `oidc`, `deadpool-postgres`, `tokio-postgres`.

`openauth-oauth-provider` is consumed as its own crate (not re-exported from `openauth`).
