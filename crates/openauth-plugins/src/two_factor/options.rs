use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::api::ApiRequest;
use openauth_core::db::User;
use openauth_core::error::OpenAuthError;

pub type SendOtpFuture = Pin<Box<dyn Future<Output = Result<(), OpenAuthError>> + Send>>;
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
    pub two_factor_table: String,
    pub totp: TotpOptions,
    pub otp: OtpOptions,
    pub backup_codes: BackupCodeOptions,
    pub skip_verification_on_enable: bool,
    pub allow_passwordless: bool,
    pub two_factor_cookie_max_age: u64,
    pub trust_device_max_age: u64,
}

impl Default for TwoFactorOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            two_factor_table: "twoFactor".to_owned(),
            totp: TotpOptions::default(),
            otp: OtpOptions::default(),
            backup_codes: BackupCodeOptions::default(),
            skip_verification_on_enable: false,
            allow_passwordless: false,
            two_factor_cookie_max_age: 10 * 60,
            trust_device_max_age: 30 * 24 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpOptions {
    pub digits: u32,
    pub period: u64,
    pub disabled: bool,
}

impl Default for TotpOptions {
    fn default() -> Self {
        Self {
            digits: 6,
            period: 30,
            disabled: false,
        }
    }
}

#[derive(Clone)]
pub struct OtpOptions {
    pub period_seconds: u64,
    pub digits: usize,
    pub allowed_attempts: u32,
    pub storage: OtpStorage,
    pub send_otp: Option<SendOtp>,
}

impl Default for OtpOptions {
    fn default() -> Self {
        Self {
            period_seconds: 3 * 60,
            digits: 6,
            allowed_attempts: 5,
            storage: OtpStorage::Plain,
            send_otp: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpStorage {
    Plain,
    Encrypted,
    Hashed,
}

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
