use std::sync::Arc;

use rustauth_core::error::RustAuthError;
use time::Duration;

/// Synchronous OTP sender callback.
///
/// The Rust plugin intentionally exposes sync callback types today. If the
/// sender needs async I/O, bridge that work in application code before
/// returning from the callback.
pub type PhoneNumberSender =
    Arc<dyn Fn(&str, &str) -> Result<(), RustAuthError> + Send + Sync + 'static>;
/// Synchronous OTP verifier callback.
///
/// Use this to delegate verification to an external OTP store or provider. The
/// callback is sync-only in the current Rust API.
pub type PhoneNumberVerifier =
    Arc<dyn Fn(&str, &str) -> Result<bool, RustAuthError> + Send + Sync + 'static>;
/// Synchronous phone-number validation callback.
pub type PhoneNumberValidator =
    Arc<dyn Fn(&str) -> Result<bool, RustAuthError> + Send + Sync + 'static>;
/// Synchronous post-verification callback receiving `(phone_number, user_id)`.
pub type PhoneNumberCallback =
    Arc<dyn Fn(&str, &str) -> Result<(), RustAuthError> + Send + Sync + 'static>;
/// Synchronous temporary value callback used during sign-up-on-verification.
pub type PhoneNumberTempValue = Arc<dyn Fn(&str) -> String + Send + Sync + 'static>;

#[derive(Clone)]
pub struct SignUpOnVerification {
    pub get_temp_email: PhoneNumberTempValue,
    pub get_temp_name: Option<PhoneNumberTempValue>,
}

#[derive(Clone)]
pub struct PhoneNumberOptions {
    pub otp_length: usize,
    pub expires_in: Duration,
    pub allowed_attempts: u32,
    pub require_verification: bool,
    /// Sync-only OTP sender callback.
    pub send_otp: Option<PhoneNumberSender>,
    /// Sync-only custom OTP verifier callback.
    pub verify_otp: Option<PhoneNumberVerifier>,
    /// Sync-only password-reset OTP sender callback.
    pub send_password_reset_otp: Option<PhoneNumberSender>,
    /// Sync-only callback invoked after successful phone verification.
    pub callback_on_verification: Option<PhoneNumberCallback>,
    /// Sync-only phone-number validator callback.
    pub phone_number_validator: Option<PhoneNumberValidator>,
    pub sign_up_on_verification: Option<SignUpOnVerification>,
    pub schema: super::schema::PhoneNumberSchemaOptions,
}

impl Default for PhoneNumberOptions {
    fn default() -> Self {
        Self {
            otp_length: 6,
            expires_in: Duration::minutes(5),
            allowed_attempts: 3,
            require_verification: false,
            send_otp: None,
            verify_otp: None,
            send_password_reset_otp: None,
            callback_on_verification: None,
            phone_number_validator: None,
            sign_up_on_verification: None,
            schema: super::schema::PhoneNumberSchemaOptions::default(),
        }
    }
}

impl PhoneNumberOptions {
    #[must_use]
    pub fn new<F>(sender: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), RustAuthError> + Send + Sync + 'static,
    {
        Self {
            send_otp: Some(Arc::new(sender)),
            ..Self::default()
        }
    }

    pub(crate) fn with_defaults(mut self) -> Self {
        if self.otp_length == 0 {
            self.otp_length = 6;
        }
        if self.expires_in == Duration::ZERO {
            self.expires_in = Duration::minutes(5);
        }
        if self.allowed_attempts == 0 {
            self.allowed_attempts = 3;
        }
        self
    }

    #[must_use]
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    #[must_use]
    pub fn send_otp<F>(mut self, sender: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), RustAuthError> + Send + Sync + 'static,
    {
        self.send_otp = Some(Arc::new(sender));
        self
    }

    #[must_use]
    pub fn verify_otp<F>(mut self, verifier: F) -> Self
    where
        F: Fn(&str, &str) -> Result<bool, RustAuthError> + Send + Sync + 'static,
    {
        self.verify_otp = Some(Arc::new(verifier));
        self
    }

    #[must_use]
    pub fn send_password_reset_otp<F>(mut self, sender: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), RustAuthError> + Send + Sync + 'static,
    {
        self.send_password_reset_otp = Some(Arc::new(sender));
        self
    }

    #[must_use]
    pub fn phone_number_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&str) -> Result<bool, RustAuthError> + Send + Sync + 'static,
    {
        self.phone_number_validator = Some(Arc::new(validator));
        self
    }

    #[must_use]
    pub fn callback_on_verification<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), RustAuthError> + Send + Sync + 'static,
    {
        self.callback_on_verification = Some(Arc::new(callback));
        self
    }

    #[must_use]
    pub fn sign_up_on_verification(mut self, options: SignUpOnVerification) -> Self {
        self.sign_up_on_verification = Some(options);
        self
    }

    #[must_use]
    pub fn require_verification(mut self, require_verification: bool) -> Self {
        self.require_verification = require_verification;
        self
    }

    pub fn validate(&self) -> Result<(), RustAuthError> {
        if self.otp_length == 0 {
            return Err(RustAuthError::InvalidConfig(
                "phone-number otp_length must be greater than zero".to_owned(),
            ));
        }
        if self.expires_in.is_zero() {
            return Err(RustAuthError::InvalidConfig(
                "phone-number expires_in must be greater than zero".to_owned(),
            ));
        }
        if self.allowed_attempts == 0 {
            return Err(RustAuthError::InvalidConfig(
                "phone-number allowed_attempts must be greater than zero".to_owned(),
            ));
        }
        if self.send_otp.is_none() {
            return Err(RustAuthError::InvalidConfig(
                "phone-number send_otp callback is required".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct PhoneNumberOptionsBuilder {
    otp_length: Option<usize>,
    expires_in: Option<Duration>,
    allowed_attempts: Option<u32>,
    require_verification: Option<bool>,
    send_otp: Option<PhoneNumberSender>,
    verify_otp: Option<PhoneNumberVerifier>,
    send_password_reset_otp: Option<PhoneNumberSender>,
    callback_on_verification: Option<PhoneNumberCallback>,
    phone_number_validator: Option<PhoneNumberValidator>,
    sign_up_on_verification: Option<SignUpOnVerification>,
    schema: Option<super::schema::PhoneNumberSchemaOptions>,
}

impl PhoneNumberOptionsBuilder {
    pub fn build(self) -> Result<PhoneNumberOptions, RustAuthError> {
        let defaults = PhoneNumberOptions::default();
        let options = PhoneNumberOptions {
            otp_length: self.otp_length.unwrap_or(defaults.otp_length),
            expires_in: self.expires_in.unwrap_or(defaults.expires_in),
            allowed_attempts: self.allowed_attempts.unwrap_or(defaults.allowed_attempts),
            require_verification: self
                .require_verification
                .unwrap_or(defaults.require_verification),
            send_otp: self.send_otp.or(defaults.send_otp),
            verify_otp: self.verify_otp.or(defaults.verify_otp),
            send_password_reset_otp: self
                .send_password_reset_otp
                .or(defaults.send_password_reset_otp),
            callback_on_verification: self
                .callback_on_verification
                .or(defaults.callback_on_verification),
            phone_number_validator: self
                .phone_number_validator
                .or(defaults.phone_number_validator),
            sign_up_on_verification: self
                .sign_up_on_verification
                .or(defaults.sign_up_on_verification),
            schema: self.schema.unwrap_or(defaults.schema),
        };
        options.validate()?;
        Ok(options)
    }
}
