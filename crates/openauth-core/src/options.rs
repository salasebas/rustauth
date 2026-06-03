//! Configuration types for OpenAuth core.

mod account;
mod advanced;
mod api_error;
mod cookies;
mod email_password;
mod email_verification;
pub(crate) mod hooks;
mod origins;
mod password;
mod rate_limit;
mod root;
mod session;
mod storage;
mod user;
mod verification;

pub use account::{AccountLinkingOptions, AccountOptions, OAuthStateStoreStrategy};
pub use advanced::{
    AdvancedOptions, BackgroundTaskFuture, BackgroundTaskRunner, CookieAttributesOverride,
    IpAddressOptions,
};
pub use api_error::{OnApiErrorHandler, OnApiErrorOptions};
pub use cookies::{CookieCacheOptions, CookieCacheStrategy, CookieConfig};
pub use email_password::{EmailPasswordOptions, ExistingUserSignUpPayload, OnExistingUserSignUp};
pub use email_verification::{
    AfterEmailVerification, BeforeEmailVerification, EmailVerificationCallbackPayload,
    EmailVerificationOptions, SendVerificationEmail, VerificationEmail,
};
pub use hooks::{GlobalAfterHook, GlobalBeforeHook, GlobalHookAction, GlobalHooksOptions};
pub use origins::{TrustedOriginOptions, TrustedOriginsProvider};
pub use password::{
    OnPasswordReset, PasswordOptions, PasswordResetEmail, PasswordResetPayload, SendResetPassword,
};
pub use rate_limit::{
    DynamicRateLimitPathRule, HybridRateLimitOptions, MissingIpPolicy, RateLimitConsumeInput,
    RateLimitDecision, RateLimitFuture, RateLimitOptions, RateLimitPathRule, RateLimitRecord,
    RateLimitRule, RateLimitRuleProvider, RateLimitStorage, RateLimitStorageOption, RateLimitStore,
};
pub use root::{ExperimentalOptions, OpenAuthOptions, TelemetryOptions};
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
