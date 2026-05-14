//! CAPTCHA errors.

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptchaConfigError {
    #[error("missing CAPTCHA secret key")]
    MissingSecretKey,
    #[error("failed to serialize CAPTCHA options: {0}")]
    SerializeOptions(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaErrorCode {
    VerificationFailed,
    MissingResponse,
    UnknownError,
}

impl CaptchaErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::MissingResponse => "MISSING_RESPONSE",
            Self::UnknownError => "UNKNOWN_ERROR",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::VerificationFailed => "Captcha verification failed",
            Self::MissingResponse => "Missing CAPTCHA response",
            Self::UnknownError => "Something went wrong",
        }
    }
}
