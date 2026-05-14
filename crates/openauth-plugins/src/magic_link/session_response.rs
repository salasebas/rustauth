use openauth_core::context::request_state::{has_request_state, set_current_new_session};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use openauth_core::db::{Session, User};
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;

pub(crate) fn record_new_session(session: &Session, user: &User) -> Result<(), OpenAuthError> {
    if has_request_state() {
        set_current_new_session(session.clone(), user.clone())?;
    }
    Ok(())
}

pub(crate) fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
) -> Result<Vec<Cookie>, OpenAuthError> {
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
                .unwrap_or(60 * 5),
        )?);
    }
    Ok(cookies)
}
