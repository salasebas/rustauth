//! Configuration types for OpenAuth core.

mod account;
mod advanced;
mod cookies;
mod email_verification;
mod origins;
mod password;
mod rate_limit;
mod root;
mod session;
mod user;

pub use account::{AccountLinkingOptions, AccountOptions, OAuthStateStoreStrategy};
pub use advanced::{AdvancedOptions, CookieAttributesOverride, IpAddressOptions};
pub use cookies::{CookieCacheOptions, CookieCacheStrategy, CookieConfig};
pub use email_verification::{
    AfterEmailVerification, BeforeEmailVerification, EmailVerificationCallbackPayload,
    EmailVerificationOptions, SendVerificationEmail, VerificationEmail,
};
pub use origins::{TrustedOriginOptions, TrustedOriginsProvider};
pub use password::{OnPasswordReset, PasswordOptions, PasswordResetPayload};
pub use rate_limit::{
    DynamicRateLimitPathRule, RateLimitOptions, RateLimitPathRule, RateLimitRecord, RateLimitRule,
    RateLimitRuleProvider, RateLimitStorage, RateLimitStorageOption,
};
pub use root::{ExperimentalOptions, OpenAuthOptions, TelemetryOptions};
pub use session::{SessionAdditionalField, SessionOptions};
pub use user::{ChangeEmailOptions, DeleteUserOptions, UserAdditionalField, UserOptions};
