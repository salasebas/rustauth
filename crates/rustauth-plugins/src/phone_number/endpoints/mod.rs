pub(crate) mod password_reset;
pub(crate) mod send_otp;
pub(crate) mod sign_in;
pub(crate) mod verify;

use http::StatusCode;
use rustauth_core::cookies::{set_session_cookie, Cookie, CookieOptions, SessionCookieOptions};
use rustauth_core::error::RustAuthError;
use rustauth_core::session::CreateSessionInput;
use time::{Duration, OffsetDateTime};

use crate::phone_number::errors::{error_response, invalid_phone_number};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::store::PhoneUser;

pub(crate) fn validate_phone_number(
    options: &PhoneNumberOptions,
    phone_number: &str,
) -> Result<Option<rustauth_core::api::ApiResponse>, RustAuthError> {
    let valid = if let Some(validator) = &options.phone_number_validator {
        validator(phone_number)?
    } else {
        !phone_number.trim().is_empty()
    };
    if valid {
        Ok(None)
    } else {
        error_response(StatusCode::BAD_REQUEST, invalid_phone_number()).map(Some)
    }
}

pub(crate) async fn create_session_cookies(
    context: &rustauth_core::context::AuthContext,
    user: &PhoneUser,
    dont_remember: bool,
) -> Result<(String, Vec<Cookie>), RustAuthError> {
    let session = context
        .sessions()?
        .create_session(CreateSessionInput::new(
            &user.id,
            OffsetDateTime::now_utc()
                + Duration::seconds(if dont_remember {
                    60 * 60 * 24
                } else {
                    context.session_config.expires_in.whole_seconds()
                }),
        ))
        .await?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember,
            overrides: CookieOptions::default(),
        },
    )?;
    Ok((session.token, cookies))
}
