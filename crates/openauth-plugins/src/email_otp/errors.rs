use openauth_core::plugin::PluginErrorCode;

pub const EMAIL_OTP_ERROR_CODES: &[(&str, &str)] = &[
    ("OTP_EXPIRED", "OTP expired"),
    ("INVALID_OTP", "Invalid OTP"),
    ("TOO_MANY_ATTEMPTS", "Too many attempts"),
    ("INVALID_OTP_TYPE", "Invalid OTP type"),
    ("INVALID_EMAIL", "Invalid email"),
    (
        "SEND_VERIFICATION_OTP_NOT_CONFIGURED",
        "send email verification is not implemented",
    ),
];

pub fn error_codes() -> impl Iterator<Item = PluginErrorCode> {
    EMAIL_OTP_ERROR_CODES
        .iter()
        .map(|(code, message)| PluginErrorCode::new(*code, *message))
}
