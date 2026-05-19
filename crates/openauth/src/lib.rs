//! OpenAuth authentication toolkit.

pub mod auth;

pub use auth::{
    open_auth, open_auth_with_adapter, open_auth_with_adapter_and_endpoints,
    open_auth_with_endpoints, OpenAuth, OpenAuthBuilder,
};
pub use openauth_core::api::{
    core_auth_async_endpoints, create_auth_endpoint, parse_request_body, ApiErrorCode,
    ApiErrorResponse, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpoint,
    AuthEndpointOptions, AuthRouter, BodyField, BodySchema, EndpointInfo, EndpointKind,
    EndpointMiddleware, JsonSchemaType, OpenApiOperation, PathParams,
};
pub use openauth_core::auth::email_password::{
    AuthFlowError, AuthFlowErrorCode, EmailPasswordAuth, EmailPasswordAuthResult,
    EmailPasswordConfig, SignInInput, SignUpInput,
};
pub use openauth_core::auth::session::{
    GetSessionInput, GetSessionResult, SessionAuth, SignOutResult,
};
pub use openauth_core::context::{AuthContext, AuthEnvironment};
pub use openauth_core::cookies::{
    AuthCookie, AuthCookies, ChunkedCookieStore, Cookie, CookieCachePayload, CookieOptions,
    ParsedCookie, SessionCookieOptions,
};
pub use openauth_core::crypto::{
    build_secret_config, parse_secrets_env, symmetric_decode_jwt, symmetric_decrypt,
    symmetric_encode_jwt, symmetric_encrypt, validate_secrets, Envelope, JweSecretSource,
    SecretConfig, SecretEntry,
};
pub use openauth_core::db::{HookedAdapter, MemoryAdapter};
pub use openauth_core::error::OpenAuthError;
pub use openauth_core::oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
pub use openauth_core::options::{
    AccountLinkingOptions, AccountOptions, AdvancedOptions, BackgroundTaskFuture,
    BackgroundTaskRunner, ChangeEmailOptions, CookieAttributesOverride, CookieCacheOptions,
    CookieCacheStrategy, CookieConfig, DeleteUserOptions, DynamicRateLimitPathRule,
    EmailVerificationOptions, ExperimentalOptions, HybridRateLimitOptions, IpAddressOptions,
    OAuthStateStoreStrategy, OpenAuthOptions, PasswordOptions, RateLimitConsumeInput,
    RateLimitDecision, RateLimitFuture, RateLimitOptions, RateLimitPathRule, RateLimitRecord,
    RateLimitRule, RateLimitRuleProvider, RateLimitStorage, RateLimitStorageOption, RateLimitStore,
    SecondaryStorage, SecondaryStorageFuture, SendVerificationEmail, SessionAdditionalField,
    SessionOptions, TelemetryOptions, TrustedOriginOptions, TrustedOriginsProvider,
    UserAdditionalField, UserOptions, VerificationEmail,
};
pub use openauth_core::plugin::{
    AuthPlugin, PluginAfterHook, PluginAfterHookAction, PluginAfterHookFuture,
    PluginAsyncAfterHook, PluginAsyncAfterHookHandler, PluginBeforeHook, PluginBeforeHookAction,
    PluginDatabaseAfterInput, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook, PluginDatabaseHookContext, PluginDatabaseOperation, PluginEndpoint,
    PluginEndpointHooks, PluginErrorCode, PluginHookMatcher, PluginInitOutput, PluginMiddleware,
    PluginMigration, PluginPasswordValidationInput, PluginPasswordValidationRejection,
    PluginPasswordValidator, PluginPasswordValidatorFuture, PluginPasswordValidatorHandler,
    PluginRateLimitRule, PluginRequestAction, PluginSchemaContribution,
};
pub use openauth_core::rate_limit::RequestClientIp;
pub use openauth_core::session::{CreateSessionInput, DbSessionStore};
pub use openauth_core::user::{
    CreateCredentialAccountInput, CreateUserInput, DbUserStore, UpdateUserInput, UserWithAccounts,
};
pub use openauth_core::verification::{
    CreateVerificationInput, DbVerificationStore, UpdateVerificationInput,
};
pub use openauth_core::{
    api, context, cookies, crypto, db, env, error, options, plugin, rate_limit, session, user,
    utils, verification,
};
pub use openauth_core::{oauth, social_providers};
#[cfg(feature = "deadpool-postgres")]
pub use openauth_deadpool_postgres as deadpool_postgres;
#[cfg(feature = "passkey")]
pub use openauth_passkey as passkey;
#[cfg(feature = "plugins")]
pub use openauth_plugins as plugins;
#[cfg(feature = "sqlx")]
pub use openauth_sqlx as sqlx;
#[cfg(feature = "sso")]
pub use openauth_sso as sso;
pub use openauth_telemetry::{
    create_telemetry, get_telemetry_auth_config, TelemetryContext, TelemetryEvent,
    TelemetryPublisher, TelemetryTestHooks,
};
#[cfg(feature = "tokio-postgres")]
pub use openauth_tokio_postgres as tokio_postgres;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
