//! Convenient re-exports for application developers mounting RustAuth.
//!
//! Library authors extending adapters, plugins, or endpoints should import from
//! the focused modules (`rustauth::db`, `rustauth::plugin`, `rustauth::api`, …)
//! instead of this prelude.
//!
//! With the `plugins` feature and optional enterprise features enabled, a single
//! import wires the full stack:
//!
//! ```rust,no_run
//! # #[cfg(all(feature = "plugins", feature = "passkey", feature = "sso"))]
//! # {
//! use rustauth::prelude::*;
//!
//! let auth = RustAuth::builder()
//!     .secret("secret-a-at-least-32-chars-long!!")
//!     .plugin(admin(AdminOptions::default()))
//!     .plugin(passkey(PasskeyOptions::default()))
//!     .plugin(sso(SsoOptions::default()))
//!     .build()?;
//! # let _ = auth;
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub use crate::auth::{RustAuth, RustAuthBuilder};
pub use crate::db::MemoryAdapter;
pub use crate::error::RustAuthError;
#[cfg(feature = "oauth")]
pub use crate::oauth::oauth2::SocialOAuthProvider;
pub use crate::options::{
    AdvancedOptions, EmailPasswordOptions, RateLimitOptions, RustAuthOptions, SessionOptions,
    TrustedOriginOptions, UserOptions,
};
pub use crate::plugin::AuthPlugin;

#[cfg(feature = "plugins")]
pub use rustauth_plugins::prelude::*;

#[cfg(feature = "passkey")]
pub use rustauth_passkey::{passkey, PasskeyOptions};

#[cfg(feature = "sso")]
pub use rustauth_sso::{sso, SsoOptions};

#[cfg(feature = "scim")]
pub use rustauth_scim::{scim, ScimOptions};

#[cfg(feature = "stripe")]
pub use rustauth_stripe::{stripe, StripeOptions};

#[cfg(feature = "oauth-provider")]
pub use rustauth_oauth_provider::{oauth_provider, OAuthProviderOptions};

#[cfg(feature = "i18n")]
pub use rustauth_i18n::{i18n, I18nOptions};
