use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_core::api::ApiRequest;
use rustauth_core::db::User;
use rustauth_core::error::RustAuthError;
use time::Duration;

pub type SendOtpFuture = Pin<Box<dyn Future<Output = Result<(), RustAuthError>> + Send>>;
pub type SendOtp = Arc<dyn Fn(TwoFactorOtpMessage) -> SendOtpFuture + Send + Sync>;

#[derive(Clone)]
pub struct TwoFactorOtpMessage {
    pub user: User,
    pub otp: String,
    pub request: ApiRequest,
}

#[derive(Clone)]
pub struct TwoFactorOptions {
    pub issuer: Option<String>,
    /// Physical database table name for two-factor secrets (`two_factors` by default).
    pub two_factor_table: String,
    pub totp: TotpOptions,
    pub otp: OtpOptions,
    pub backup_codes: BackupCodeOptions,
    pub skip_verification_on_enable: bool,
    pub allow_passwordless: bool,
    pub two_factor_cookie_max_age: Duration,
    pub trust_device_max_age: Duration,
}

impl Default for TwoFactorOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            two_factor_table: "two_factors".to_owned(),
            totp: TotpOptions::default(),
            otp: OtpOptions::default(),
            backup_codes: BackupCodeOptions::default(),
            skip_verification_on_enable: false,
            allow_passwordless: false,
            two_factor_cookie_max_age: Duration::minutes(10),
            trust_device_max_age: Duration::days(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpOptions {
    pub digits: u32,
    pub period: Duration,
    pub disabled: bool,
}

impl Default for TotpOptions {
    fn default() -> Self {
        Self {
            digits: 6,
            period: Duration::seconds(30),
            disabled: false,
        }
    }
}

#[derive(Clone)]
pub struct OtpOptions {
    pub period: Duration,
    pub digits: usize,
    pub allowed_attempts: u32,
    pub storage: OtpStorage,
    pub send_otp: Option<SendOtp>,
}

impl Default for OtpOptions {
    fn default() -> Self {
        Self {
            period: Duration::minutes(3),
            digits: 6,
            allowed_attempts: 5,
            storage: OtpStorage::Plain,
            send_otp: None,
        }
    }
}

pub use super::otp_storage::{OtpDecryptFn, OtpEncryptFn, OtpHashFn, OtpStorage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupCodeOptions {
    pub amount: usize,
    pub length: usize,
    pub storage: BackupCodeStorage,
}

impl Default for BackupCodeOptions {
    fn default() -> Self {
        Self {
            amount: 10,
            length: 10,
            storage: BackupCodeStorage::Encrypted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupCodeStorage {
    Plain,
    Encrypted,
}

#[derive(Clone, Default)]
pub struct TwoFactorOptionsBuilder {
    issuer: Option<Option<String>>,
    two_factor_table: Option<String>,
    totp: Option<TotpOptions>,
    otp: Option<OtpOptions>,
    backup_codes: Option<BackupCodeOptions>,
    skip_verification_on_enable: Option<bool>,
    allow_passwordless: Option<bool>,
    two_factor_cookie_max_age: Option<Duration>,
    trust_device_max_age: Option<Duration>,
}

impl TwoFactorOptionsBuilder {
    pub fn build(self) -> TwoFactorOptions {
        let defaults = TwoFactorOptions::default();
        TwoFactorOptions {
            issuer: self.issuer.unwrap_or(defaults.issuer),
            two_factor_table: self.two_factor_table.unwrap_or(defaults.two_factor_table),
            totp: self.totp.unwrap_or(defaults.totp),
            otp: self.otp.unwrap_or(defaults.otp),
            backup_codes: self.backup_codes.unwrap_or(defaults.backup_codes),
            skip_verification_on_enable: self
                .skip_verification_on_enable
                .unwrap_or(defaults.skip_verification_on_enable),
            allow_passwordless: self
                .allow_passwordless
                .unwrap_or(defaults.allow_passwordless),
            two_factor_cookie_max_age: self
                .two_factor_cookie_max_age
                .unwrap_or(defaults.two_factor_cookie_max_age),
            trust_device_max_age: self
                .trust_device_max_age
                .unwrap_or(defaults.trust_device_max_age),
        }
    }
}

impl TwoFactorOptions {
    #[must_use]
    pub fn builder() -> TwoFactorOptionsBuilder {
        TwoFactorOptionsBuilder::default()
    }
}
