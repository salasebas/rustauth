//! OpenAuth authentication toolkit.

pub mod auth;

pub use auth::{open_auth, open_auth_with_endpoints, OpenAuth};
pub use openauth_core::api::{
    core_auth_async_endpoints, create_auth_endpoint, parse_request_body, ApiErrorCode,
    ApiErrorResponse, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpoint,
    AuthEndpointOptions, AuthRouter, BodyField, BodySchema, EndpointInfo, EndpointKind,
    EndpointMiddleware, JsonSchemaType, OpenApiOperation,
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
pub use openauth_core::error::OpenAuthError;
pub use openauth_core::options::{
    AdvancedOptions, CookieAttributesOverride, CookieCacheOptions, CookieCacheStrategy,
    CookieConfig, DynamicRateLimitPathRule, IpAddressOptions, OpenAuthOptions, PasswordOptions,
    RateLimitOptions, RateLimitPathRule, RateLimitRecord, RateLimitRule, RateLimitRuleProvider,
    RateLimitStorage, RateLimitStorageOption, SessionOptions, TrustedOriginOptions,
    TrustedOriginsProvider,
};
pub use openauth_core::plugin::{AuthPlugin, PluginMiddleware, PluginRequestAction};
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

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
