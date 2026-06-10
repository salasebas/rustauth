pub(crate) mod password_reset;
pub(crate) mod send_otp;
pub(crate) mod sign_in;
pub(crate) mod verify;

use std::sync::Arc;

use http::StatusCode;
use openauth_core::context::AuthContext;
use openauth_core::cookies::{set_session_cookie, Cookie, CookieOptions, SessionCookieOptions};
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use time::{Duration, OffsetDateTime};

use crate::phone_number::errors::{error_response, invalid_phone_number};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::store::PhoneUser;

pub(crate) fn require_adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("phone-number plugin requires a database adapter".to_owned())
    })
}

pub(crate) fn validate_phone_number(
    options: &PhoneNumberOptions,
    phone_number: &str,
) -> Result<Option<openauth_core::api::ApiResponse>, OpenAuthError> {
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
    adapter: &dyn openauth_core::db::DbAdapter,
    context: &openauth_core::context::AuthContext,
    user: &PhoneUser,
    dont_remember: bool,
) -> Result<(String, Vec<Cookie>), OpenAuthError> {
    let session = DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            &user.id,
            OffsetDateTime::now_utc()
                + Duration::seconds(if dont_remember {
                    60 * 60 * 24
                } else {
                    context.session_config.expires_in as i64
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
