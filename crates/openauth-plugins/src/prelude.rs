//! Convenient re-exports for wiring official plugins into `OpenAuth`.
//!
//! ```rust
//! use openauth::OpenAuth;
//! use openauth_plugins::prelude::*;
//!
//! let auth = OpenAuth::builder()
//!     .secret("secret-a-at-least-32-chars-long!!")
//!     .plugin(admin())
//!     .plugin(jwt()?)
//!     .build()?;
//! # let _ = auth;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub use crate::access::{
    create_access_control, request as access_request, role, statements, AccessControl,
    AccessRequest,
};
pub use crate::additional_fields::{additional_fields_with, AdditionalFieldsOptions};
pub use crate::admin::{admin, admin_with, AdminOptions};
pub use crate::anonymous::{anonymous, anonymous_with, AnonymousOptions};
pub use crate::api_key::{
    api_key, api_key_with, ApiKeyConfiguration, ApiKeyOptions, ApiKeyOptionsBuilder,
    ApiKeySchemaOptions,
};
pub use crate::bearer::{bearer, bearer_with, BearerOptions};
pub use crate::captcha::{captcha_with, CaptchaOptions};
pub use crate::custom_session::{custom_session, custom_session_with, CustomSessionOptions};
pub use crate::device_authorization::{
    device_authorization, device_authorization_with, DeviceAuthorizationOptions,
};
pub use crate::email_otp::{email_otp, email_otp_with, EmailOtpOptions};
pub use crate::generic_oauth::{generic_oauth_with, GenericOAuthOptions};
pub use crate::have_i_been_pwned::{
    have_i_been_pwned, have_i_been_pwned_with, HaveIBeenPwnedChecker, HaveIBeenPwnedOptions,
};
pub use crate::jwt::{jwt, jwt_with, JwtOptions};
pub use crate::last_login_method::{
    last_login_method, last_login_method_with, LastLoginMethodOptions,
};
pub use crate::magic_link::{magic_link_with, MagicLinkOptions};
pub use crate::multi_session::{multi_session, multi_session_with, MultiSessionConfig};
pub use crate::oauth_proxy::{oauth_proxy, oauth_proxy_with, OAuthProxyOptions};
pub use crate::one_tap::{one_tap, one_tap_with, OneTapOptions};
pub use crate::one_time_token::{one_time_token, one_time_token_with, OneTimeTokenOptions};
pub use crate::open_api::{open_api, open_api_with, OpenApiOptions};
pub use crate::organization::{
    organization, organization_with, OrganizationOptions, OrganizationOptionsBuilder,
};
pub use crate::phone_number::{phone_number, phone_number_with, PhoneNumberOptions};
pub use crate::siwe::{siwe_with, SiweOptions};
pub use crate::two_factor::{two_factor, two_factor_with, TwoFactorOptions};
pub use crate::username::{username, username_with, UsernameOptions};

pub use openauth_core::plugin::AuthPlugin;
