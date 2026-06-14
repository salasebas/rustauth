//! Populate request-scoped session user for hooks (e.g. i18n session locale detection).

use crate::auth::session::{GetSessionInput, SessionAuth};
use crate::context::request_state::{
    current_session_user, has_request_state, set_current_session_user,
};
use crate::context::AuthContext;
use crate::error::RustAuthError;

use http::header;

use super::endpoint::ApiRequest;
use super::output::user_output_value;

fn request_cookie_header(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// When request state is active and no session user is set yet, resolve the session from
/// cookies and store the user JSON for sync hooks such as i18n `session` detection.
pub(super) async fn ensure_session_user_in_request_state(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<(), RustAuthError> {
    if !has_request_state() {
        return Ok(());
    }
    if current_session_user()?.is_some() {
        return Ok(());
    }
    let Some(adapter) = context.adapter.as_deref() else {
        return Ok(());
    };
    let cookie_header = request_cookie_header(request).unwrap_or_default();
    if cookie_header.is_empty() {
        return Ok(());
    }
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(());
    };
    let Some(user) = result.user else {
        return Ok(());
    };
    set_current_session_user(user_output_value(adapter, context, &user).await?)?;
    Ok(())
}
