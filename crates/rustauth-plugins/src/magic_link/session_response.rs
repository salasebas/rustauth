use rustauth_core::api::output::session_output_value;
use rustauth_core::context::request_state::{has_request_state, set_current_new_session};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use rustauth_core::db::{DbAdapter, DbRecord, DbValue, Session, User};
use rustauth_core::error::RustAuthError;
use rustauth_core::rate_limit::resolve_client_ip;
use rustauth_core::session::CreateSessionInput;
use serde_json::Value;
use time::OffsetDateTime;

pub(crate) fn session_create_input(
    context: &AuthContext,
    request: &http::Request<Vec<u8>>,
    user_id: String,
    expires_at: OffsetDateTime,
) -> CreateSessionInput {
    let mut input = CreateSessionInput::new(user_id, expires_at)
        .additional_fields(additional_session_create_values(context));
    if let Some(ip_address) = resolve_client_ip(context, request) {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = request_user_agent(request) {
        input = input.user_agent(user_agent);
    }
    input
}

pub(crate) fn record_new_session(session: &Session, user: &User) -> Result<(), RustAuthError> {
    if has_request_state() {
        set_current_new_session(session.clone(), user.clone())?;
    }
    Ok(())
}

pub(crate) fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
) -> Result<Vec<Cookie>, RustAuthError> {
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember: false,
            overrides: CookieOptions::default(),
        },
    )?;
    if context.options.session.cookie_cache.enabled {
        let payload = CookieCachePayload {
            session: session.clone(),
            user: user.clone(),
            updated_at: OffsetDateTime::now_utc().unix_timestamp(),
            version: context
                .options
                .session
                .cookie_cache
                .version
                .clone()
                .unwrap_or_else(|| "1".to_owned()),
        };
        cookies.extend(set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &payload,
            context.options.session.cookie_cache.strategy,
            context
                .options
                .session
                .cookie_cache
                .max_age
                .unwrap_or(time::Duration::minutes(5))
                .whole_seconds() as u64,
        )?);
    }
    Ok(cookies)
}

pub(crate) async fn session_response_value(
    _adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
) -> Result<Value, RustAuthError> {
    session_output_value(context.adapter_ref()?, context, session).await
}

fn additional_session_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}

fn request_user_agent(request: &http::Request<Vec<u8>>) -> Option<String> {
    request
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
