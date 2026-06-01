use http::header;
use openauth_core::api::ApiRequest;
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::cookies::Cookie;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, Session, User};
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, SessionStore};
use time::{Duration, OffsetDateTime};

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
) -> Result<Option<CurrentSession>, OpenAuthError> {
    let Some(adapter) = context.adapter() else {
        return Ok(None);
    };
    let cookie_header = request_cookie_header(request).unwrap_or_default();
    let Some(result) = SessionAuth::new(adapter.as_ref(), context)
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
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
    user: &User,
) -> Result<Session, OpenAuthError> {
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64);
    let mut input = CreateSessionInput::new(user.id.clone(), expires_at);
    if let Some(ip_address) = openauth_core::rate_limit::resolve_client_ip(context, request) {
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
    SessionStore::new(adapter, context)
        .create_session(input)
        .await
}

pub fn session_is_fresh(context: &AuthContext, session: &Session) -> bool {
    context.session_config.fresh_age == 0
        || (OffsetDateTime::now_utc() - session.created_at).whole_seconds()
            < context.session_config.fresh_age as i64
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
