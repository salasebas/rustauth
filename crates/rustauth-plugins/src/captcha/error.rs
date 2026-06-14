//! CAPTCHA errors.

use rustauth_core::error_codes::ErrorCode;

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
            Self::UnknownError => "CAPTCHA_UNKNOWN_ERROR",
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

impl ErrorCode for CaptchaErrorCode {
    fn as_str(&self) -> &str {
        (*self).as_str()
    }

    fn message(&self) -> &str {
        (*self).message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustauth_core::error_codes::ErrorCode;

    fn assert_error_code(code: impl ErrorCode, expected_code: &str, expected_message: &str) {
        assert_eq!(code.as_str(), expected_code);
        assert_eq!(code.message(), expected_message);
    }

    #[test]
    fn captcha_error_code_implements_error_code_trait() {
        assert_error_code(
            CaptchaErrorCode::VerificationFailed,
            "VERIFICATION_FAILED",
            "Captcha verification failed",
        );
    }
}
