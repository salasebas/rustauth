//! Configuration types for RustAuth core.
//!
//! # Hooks
//!
//! RustAuth supports three hook registration paths:
//!
//! 1. **Global HTTP hooks** — build [`GlobalHooksOptions`] and register it with
//!    [`RustAuthOptions::hooks`]. These run before/after matched API endpoints
//!    (parity with Better Auth `hooks`).
//! 2. **Init-time database hooks** — build [`InitDatabaseHooksOptions`] and register
//!    it with [`RustAuthOptions::init_database_hooks`]. Prefer this for typed
//!    create/update callbacks on core models (`user`, `session`, `account`,
//!    `verification`). See [`RustAuthOptions`] for when to combine this with
//!    low-level hooks.
//! 3. **Low-level plugin database hooks** — append [`crate::plugin::PluginDatabaseHook`]
//!    via [`RustAuthOptions::database_hook`] for custom models, plugin-owned tables,
//!    or operations that do not fit the init-time schema.

mod account;
mod advanced;
mod api_error;
mod cookies;
mod email_password;
mod email_verification;
pub(crate) mod hooks;
mod init_database_hooks;
mod model_schema;
mod origins;
mod password;
mod rate_limit;
mod root;
mod session;
mod storage;
mod user;
mod verification;

pub use account::{
    AccountLinkingOptions, AccountOptions, OAuthStateStoreStrategy, TrustedProvidersProvider,
    TrustedProvidersRequestProvider,
};
pub use advanced::{
    AdvancedOptions, BackgroundTaskFuture, BackgroundTaskRunner, CookieAttributesOverride,
    IpAddressOptions,
};
pub use api_error::{DefaultErrorPage, OnApiErrorHandler, OnApiErrorOptions};
pub use cookies::{CookieCacheOptions, CookieCacheStrategy, CookieConfig};
pub use email_password::{EmailPasswordOptions, ExistingUserSignUpPayload, OnExistingUserSignUp};
pub use email_verification::{
    AfterEmailVerification, BeforeEmailVerification, EmailVerificationCallbackPayload,
    EmailVerificationOptions, SendVerificationEmail, VerificationEmail,
};
pub use hooks::{GlobalAfterHook, GlobalBeforeHook, GlobalHookAction, GlobalHooksOptions};
pub use init_database_hooks::{
    plugin_database_hooks_from_init, DatabaseModelHooks, DatabaseOperationHooks,
    InitDatabaseAfterHook, InitDatabaseBeforeAction, InitDatabaseBeforeHook,
    InitDatabaseHooksOptions,
};
pub use model_schema::ModelSchemaOptions;
pub use origins::{TrustedOriginOptions, TrustedOriginsProvider};
pub use password::{
    OnPasswordReset, PasswordOptions, PasswordResetEmail, PasswordResetPayload, SendResetPassword,
};
pub use rate_limit::{
    validate_rate_limit_rule, DynamicRateLimitPathRule, HybridRateLimitOptions, MissingIpPolicy,
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitOptions, RateLimitPathRule,
    RateLimitRecord, RateLimitRule, RateLimitRuleProvider, RateLimitStorage,
    RateLimitStorageOption, RateLimitStore,
};
pub use root::{DeploymentMode, ExperimentalOptions, RustAuthOptions, TelemetryOptions};
pub use session::{SessionAdditionalField, SessionOptions};
pub use storage::{SecondaryStorage, SecondaryStorageFuture};
pub use user::{
    AfterDeleteUser, BeforeDeleteUser, ChangeEmailConfirmation, ChangeEmailOptions,
    DeleteAccountVerificationEmail, DeleteUserOptions, SendChangeEmailConfirmation,
    SendDeleteAccountVerification, UserAdditionalField, UserOptions,
};
pub use verification::{
    StoreIdentifierHashFn, StoreIdentifierHashFuture, StoreIdentifierOption, VerificationOptions,
    VerificationStoreIdentifierConfig,
};
