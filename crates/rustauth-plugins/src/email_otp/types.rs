use std::fmt;
use std::sync::Arc;

use http::Request;
use rustauth_core::error::RustAuthError;
use rustauth_core::outbound::OutboundSendFuture;
use time::Duration;

use rustauth_core::options::RateLimitRule;

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
    fn hash_otp(&self, otp: &str) -> Result<String, RustAuthError>;
}

impl<F> EmailOtpHasher for F
where
    F: Fn(&str) -> Result<String, RustAuthError> + Send + Sync + 'static,
{
    fn hash_otp(&self, otp: &str) -> Result<String, RustAuthError> {
        self(otp)
    }
}

pub trait EmailOtpEncryptor: Send + Sync + 'static {
    fn encrypt_otp(&self, otp: &str) -> Result<String, RustAuthError>;
    fn decrypt_otp(&self, stored: &str) -> Result<String, RustAuthError>;
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
    ) -> OutboundSendFuture;
}

impl<F> SendEmailOtp for F
where
    F: for<'a> Fn(EmailOtpPayload, Option<&'a Request<Vec<u8>>>) -> OutboundSendFuture
        + Send
        + Sync
        + 'static,
{
    fn send_email_otp(
        &self,
        payload: EmailOtpPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> OutboundSendFuture {
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
    pub expires_in: Duration,
    pub send_verification_on_sign_up: bool,
    pub override_default_email_verification: bool,
    pub disable_sign_up: bool,
    pub allowed_attempts: u32,
    pub store_otp: OtpStorage,
    pub resend_strategy: ResendStrategy,
    pub change_email: ChangeEmailOptions,
    pub rate_limit: Option<RateLimitRule>,
}

impl EmailOtpOptions {
    #[must_use]
    pub fn new(sender: Arc<dyn SendEmailOtp>) -> Self {
        Self {
            sender: Some(sender),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn builder() -> EmailOtpOptionsBuilder {
        EmailOtpOptionsBuilder::default()
    }

    #[must_use]
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    pub fn validate(&self) -> Result<(), RustAuthError> {
        if self.sender.is_none() {
            return Err(RustAuthError::InvalidConfig(
                "email-otp plugin requires a sender callback".to_owned(),
            ));
        }
        if self.otp_length == 0 {
            return Err(RustAuthError::InvalidConfig(
                "email-otp otp_length must be greater than zero".to_owned(),
            ));
        }
        if self.allowed_attempts == 0 {
            return Err(RustAuthError::InvalidConfig(
                "email-otp allowed_attempts must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct EmailOtpOptionsBuilder {
    sender: Option<Arc<dyn SendEmailOtp>>,
    generator: Option<Arc<dyn EmailOtpGenerator>>,
    otp_length: Option<usize>,
    expires_in: Option<Duration>,
    send_verification_on_sign_up: Option<bool>,
    override_default_email_verification: Option<bool>,
    disable_sign_up: Option<bool>,
    allowed_attempts: Option<u32>,
    store_otp: Option<OtpStorage>,
    resend_strategy: Option<ResendStrategy>,
    change_email: Option<ChangeEmailOptions>,
    rate_limit: Option<Option<RateLimitRule>>,
}

impl EmailOtpOptionsBuilder {
    #[must_use]
    pub fn sender(mut self, sender: Arc<dyn SendEmailOtp>) -> Self {
        self.sender = Some(sender);
        self
    }

    pub fn build(self) -> Result<EmailOtpOptions, RustAuthError> {
        let defaults = EmailOtpOptions::default();
        let options = EmailOtpOptions {
            sender: self.sender,
            generator: self.generator,
            otp_length: self.otp_length.unwrap_or(defaults.otp_length),
            expires_in: self.expires_in.unwrap_or(defaults.expires_in),
            send_verification_on_sign_up: self
                .send_verification_on_sign_up
                .unwrap_or(defaults.send_verification_on_sign_up),
            override_default_email_verification: self
                .override_default_email_verification
                .unwrap_or(defaults.override_default_email_verification),
            disable_sign_up: self.disable_sign_up.unwrap_or(defaults.disable_sign_up),
            allowed_attempts: self.allowed_attempts.unwrap_or(defaults.allowed_attempts),
            store_otp: self.store_otp.unwrap_or(defaults.store_otp),
            resend_strategy: self.resend_strategy.unwrap_or(defaults.resend_strategy),
            change_email: self.change_email.unwrap_or(defaults.change_email),
            rate_limit: self.rate_limit.unwrap_or(defaults.rate_limit),
        };
        options.validate()?;
        Ok(options)
    }
}

impl Default for EmailOtpOptions {
    fn default() -> Self {
        Self {
            sender: None,
            generator: None,
            otp_length: 6,
            expires_in: Duration::minutes(5),
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
