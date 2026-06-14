//! Convenient re-exports for wiring official plugins into `RustAuth`.
//!
//! ```rust
//! use rustauth_plugins::prelude::*;
//!
//! let plugins = [
//!     admin(AdminOptions::default())?,
//!     bearer(BearerOptions::default()),
//!     jwt(JwtOptions::default())?,
//! ];
//! # Ok::<(), rustauth_core::error::RustAuthError>(())
//! ```

pub use crate::access::{
    create_access_control, request as access_request, role, statements, AccessControl, AccessError,
    AccessRequest, Role as AccessRole,
};
pub use crate::additional_fields::{
    additional_fields, AdditionalField, AdditionalFieldsOptions, AdditionalFieldsOptionsBuilder,
};
pub use crate::admin::{admin, AdminOptions, AdminOptionsBuilder, AdminRole, AdminSchemaOptions};
pub use crate::anonymous::{anonymous, AnonymousOptions, AnonymousOptionsBuilder};
pub use crate::api_key::{
    api_key, ApiKeyConfiguration, ApiKeyOptions, ApiKeyOptionsBuilder, ApiKeySchemaOptions,
};
pub use crate::bearer::{bearer, BearerOptions, BearerOptionsBuilder};
pub use crate::captcha::{captcha, CaptchaOptions, CaptchaOptionsBuilder, CaptchaProvider};
pub use crate::custom_session::{
    custom_session, CustomSessionContext, CustomSessionInput, CustomSessionOptions,
    CustomSessionOptionsBuilder,
};
pub use crate::device_authorization::{
    device_authorization, DeviceAuthorizationOptions, DeviceAuthorizationOptionsBuilder,
};
pub use crate::email_otp::{email_otp, EmailOtpOptions, EmailOtpOptionsBuilder};
pub use crate::generic_oauth::{generic_oauth, GenericOAuthOptions, GenericOAuthOptionsBuilder};
pub use crate::have_i_been_pwned::{
    have_i_been_pwned, HaveIBeenPwnedChecker, HaveIBeenPwnedOptions, HaveIBeenPwnedOptionsBuilder,
};
pub use crate::jwt::{jwt, JwtOptions, JwtOptionsBuilder};
pub use crate::last_login_method::{
    last_login_method, LastLoginMethodOptions, LastLoginMethodOptionsBuilder,
};
pub use crate::magic_link::{
    magic_link, magic_link_dev_log, MagicLinkOptions, MagicLinkOptionsBuilder,
};
pub use crate::multi_session::{multi_session, MultiSessionOptions, MultiSessionOptionsBuilder};
pub use crate::oauth_proxy::{oauth_proxy, OAuthProxyOptions, OAuthProxyOptionsBuilder};
pub use crate::one_tap::{one_tap, OneTapOptions, OneTapOptionsBuilder};
pub use crate::one_time_token::{one_time_token, OneTimeTokenOptions, OneTimeTokenOptionsBuilder};
pub use crate::open_api::{open_api, OpenApiOptions, OpenApiOptionsBuilder};
pub use crate::organization::{organization, OrganizationOptions, OrganizationOptionsBuilder};
pub use crate::phone_number::{phone_number, PhoneNumberOptions, PhoneNumberOptionsBuilder};
pub use crate::siwe::{siwe, siwe_dev, siwe_dev_domain, SiweOptions, SiweOptionsBuilder};
pub use crate::two_factor::{two_factor, TwoFactorOptions, TwoFactorOptionsBuilder};
pub use crate::username::{username, UsernameOptions, UsernameOptionsBuilder};

pub use rustauth_core::plugin::AuthPlugin;
