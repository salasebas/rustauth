use std::fmt;
use std::sync::Arc;

use http::Request;
use openauth_core::error::OpenAuthError;
use openauth_core::options::RateLimitRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailOtpType {
    EmailVerification,
    SignIn,
    ForgetPassword,
    ChangeEmail,
}

impl EmailOtpType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email-verification",
            Self::SignIn => "sign-in",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }
}

impl TryFrom<&str> for EmailOtpType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "email-verification" => Ok(Self::EmailVerification),
            "sign-in" => Ok(Self::SignIn),
            "forget-password" => Ok(Self::ForgetPassword),
            "change-email" => Ok(Self::ChangeEmail),
            _ => Err(()),
        }
    }
}

pub trait EmailOtpHasher: Send + Sync + 'static {
    fn hash_otp(&self, otp: &str) -> Result<String, OpenAuthError>;
}

impl<F> EmailOtpHasher for F
where
    F: Fn(&str) -> Result<String, OpenAuthError> + Send + Sync + 'static,
{
    fn hash_otp(&self, otp: &str) -> Result<String, OpenAuthError> {
        self(otp)
    }
}

pub trait EmailOtpEncryptor: Send + Sync + 'static {
    fn encrypt_otp(&self, otp: &str) -> Result<String, OpenAuthError>;
    fn decrypt_otp(&self, stored: &str) -> Result<String, OpenAuthError>;
}

#[derive(Clone, Default)]
pub enum OtpStorage {
    #[default]
    Plain,
    Hashed,
    Encrypted,
    CustomHash(Arc<dyn EmailOtpHasher>),
    CustomEncrypt(Arc<dyn EmailOtpEncryptor>),
}

impl fmt::Debug for OtpStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => formatter.write_str("Plain"),
            Self::Hashed => formatter.write_str("Hashed"),
            Self::Encrypted => formatter.write_str("Encrypted"),
            Self::CustomHash(_) => formatter.write_str("CustomHash(<hasher>)"),
            Self::CustomEncrypt(_) => formatter.write_str("CustomEncrypt(<encryptor>)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResendStrategy {
    #[default]
    Rotate,
    Reuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    pub verify_current_email: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailOtpPayload {
    pub email: String,
    pub otp: String,
    pub otp_type: EmailOtpType,
}

pub trait SendEmailOtp: Send + Sync + 'static {
    fn send_email_otp(
        &self,
        payload: EmailOtpPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> SendEmailOtp for F
where
    F: for<'a> Fn(EmailOtpPayload, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn send_email_otp(
        &self,
        payload: EmailOtpPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

pub trait EmailOtpGenerator: Send + Sync + 'static {
    fn generate_otp(&self, email: &str, otp_type: EmailOtpType, length: usize) -> String;
}

impl<F> EmailOtpGenerator for F
where
    F: Fn(&str, EmailOtpType, usize) -> String + Send + Sync + 'static,
{
    fn generate_otp(&self, email: &str, otp_type: EmailOtpType, length: usize) -> String {
        self(email, otp_type, length)
    }
}

#[derive(Clone)]
pub struct EmailOtpOptions {
    pub sender: Option<Arc<dyn SendEmailOtp>>,
    pub generator: Option<Arc<dyn EmailOtpGenerator>>,
    pub otp_length: usize,
    pub expires_in: u64,
    pub send_verification_on_sign_up: bool,
    pub override_default_email_verification: bool,
    pub disable_sign_up: bool,
    pub allowed_attempts: u32,
    pub store_otp: OtpStorage,
    pub resend_strategy: ResendStrategy,
    pub change_email: ChangeEmailOptions,
    pub rate_limit: Option<RateLimitRule>,
}

impl Default for EmailOtpOptions {
    fn default() -> Self {
        Self {
            sender: None,
            generator: None,
            otp_length: 6,
            expires_in: 5 * 60,
            send_verification_on_sign_up: false,
            override_default_email_verification: false,
            disable_sign_up: false,
            allowed_attempts: 3,
            store_otp: OtpStorage::Plain,
            resend_strategy: ResendStrategy::Rotate,
            change_email: ChangeEmailOptions::default(),
            rate_limit: None,
        }
    }
}

impl fmt::Debug for EmailOtpOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailOtpOptions")
            .field("sender", &self.sender.as_ref().map(|_| "<sender>"))
            .field("generator", &self.generator.as_ref().map(|_| "<generator>"))
            .field("otp_length", &self.otp_length)
            .field("expires_in", &self.expires_in)
            .field(
                "send_verification_on_sign_up",
                &self.send_verification_on_sign_up,
            )
            .field(
                "override_default_email_verification",
                &self.override_default_email_verification,
            )
            .field("disable_sign_up", &self.disable_sign_up)
            .field("allowed_attempts", &self.allowed_attempts)
            .field("store_otp", &self.store_otp)
            .field("resend_strategy", &self.resend_strategy)
            .field("change_email", &self.change_email)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}
