//! Two-factor authentication plugin.

mod backup_codes;
mod cookies;
mod errors;
mod flow;
mod options;
mod otp;
mod otp_routes;
mod otp_storage;
mod payloads;
mod routes;
mod schema;
mod store;
mod totp;

pub use backup_codes::{decode_backup_codes, encode_backup_codes, generate_backup_codes};
pub use errors::TWO_FACTOR_ERROR_CODES;
pub use options::{
    BackupCodeOptions, BackupCodeStorage, OtpDecryptFn, OtpEncryptFn, OtpHashFn, OtpOptions,
    OtpStorage, SendOtp, TotpOptions, TwoFactorOptions,
};
pub use totp::{totp_code, totp_uri, verify_totp_code};

use openauth_core::plugin::AuthPlugin;

pub const UPSTREAM_PLUGIN_ID: &str = "two-factor";

#[must_use]
pub fn two_factor() -> AuthPlugin {
    two_factor_with(TwoFactorOptions::default())
}

#[must_use]
pub fn two_factor_with(options: TwoFactorOptions) -> AuthPlugin {
    let options = std::sync::Arc::new(options);
    routes::plugin(options)
}
