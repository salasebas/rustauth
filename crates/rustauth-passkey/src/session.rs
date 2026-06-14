use http::header;
use rustauth_core::api::ApiRequest;
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::Cookie;
use rustauth_core::db::{DbRecord, DbValue, Session, User};
use rustauth_core::error::RustAuthError;
use rustauth_core::session::CreateSessionInput;
use time::OffsetDateTime;

use crate::cookies::request_cookie_header;
use crate::options::{PasskeyOptions, PasskeyRegistrationUser, ResolveRegistrationUserInput};

pub type CurrentSession = (Session, User, Vec<Cookie>);

pub async fn registration_user(
    options: &PasskeyOptions,
    session: Option<&CurrentSession>,
    context: Option<String>,
) -> Result<PasskeyRegistrationUser, RegistrationUserError> {
    if options.registration.require_session {
        return session
            .map(|(_, user, _)| session_user(user))
            .ok_or(RegistrationUserError::SessionRequired);
    }
    if let Some((_, user, _)) = session {
        return Ok(session_user(user));
    }
    let Some(resolve_user) = &options.registration.resolve_user else {
        return Err(RegistrationUserError::ResolveUserRequired);
    };
    let Some(user) = resolve_user(ResolveRegistrationUserInput { context }).await else {
        return Err(RegistrationUserError::ResolvedUserInvalid);
    };
    if user.id.is_empty() || user.name.is_empty() {
        return Err(RegistrationUserError::ResolvedUserInvalid);
    }
    Ok(user)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationUserError {
    SessionRequired,
    ResolveUserRequired,
    ResolvedUserInvalid,
}

fn session_user(user: &User) -> PasskeyRegistrationUser {
    let name = if user.email.is_empty() {
        user.id.clone()
    } else {
        user.email.clone()
    };
    PasskeyRegistrationUser {
        id: user.id.clone(),
        name: name.clone(),
        display_name: Some(name),
    }
}

pub async fn current_session(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<CurrentSession>, RustAuthError> {
    let cookie_header = request_cookie_header(request).unwrap_or_default();
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    Ok(Some((session, user, result.cookies)))
}

pub async fn create_session_for_user(
    context: &AuthContext,
    request: &ApiRequest,
    user: &User,
) -> Result<Session, RustAuthError> {
    let expires_at = OffsetDateTime::now_utc() + context.session_config.expires_in;
    let mut input = CreateSessionInput::new(user.id.clone(), expires_at);
    if let Some(ip_address) = rustauth_core::rate_limit::resolve_client_ip(context, request) {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    {
        input = input.user_agent(user_agent);
    }
    input = input.additional_fields(additional_session_create_values(context));
    context.sessions()?.create_session(input).await
}

pub fn session_is_fresh(context: &AuthContext, session: &Session) -> bool {
    context.session_config.fresh_age.is_zero()
        || (OffsetDateTime::now_utc() - session.created_at).whole_seconds()
            < context.session_config.fresh_age.whole_seconds()
}

fn additional_session_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                field.db_name.clone().unwrap_or_else(|| name.clone()),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}
