//! Stable API error code strings (parity with Better Auth `BASE_ERROR_CODES`).

/// Stable RustAuth error-code metadata.
pub trait ErrorCode {
    fn as_str(&self) -> &str;
    fn message(&self) -> &str;
}

impl<T> ErrorCode for &T
where
    T: ErrorCode,
{
    fn as_str(&self) -> &str {
        (*self).as_str()
    }

    fn message(&self) -> &str {
        (*self).message()
    }
}

pub const INVALID_EMAIL: &str = "INVALID_EMAIL";
pub const INVALID_PASSWORD: &str = "INVALID_PASSWORD";
pub const INVALID_EMAIL_OR_PASSWORD: &str = "INVALID_EMAIL_OR_PASSWORD";
pub const INVALID_TOKEN: &str = "INVALID_TOKEN";
pub const INVALID_REQUEST_BODY: &str = "INVALID_REQUEST_BODY";
pub const FIELD_NOT_ALLOWED: &str = "FIELD_NOT_ALLOWED";
pub const USER_ALREADY_EXISTS: &str = "USER_ALREADY_EXISTS";
pub const USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: &str = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL";
pub const EMAIL_NOT_VERIFIED: &str = "EMAIL_NOT_VERIFIED";
pub const SESSION_EXPIRED: &str = "SESSION_EXPIRED";
pub const SESSION_NOT_FRESH: &str = "SESSION_NOT_FRESH";
pub const CREDENTIAL_ACCOUNT_NOT_FOUND: &str = "CREDENTIAL_ACCOUNT_NOT_FOUND";
pub const NOT_FOUND: &str = "NOT_FOUND";
pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
