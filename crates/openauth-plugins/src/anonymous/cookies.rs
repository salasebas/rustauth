use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, SessionCookieOptions,
};
use openauth_core::db::Session;
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;

use super::model::AnonymousUser;

pub fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &AnonymousUser,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions::default(),
    )?;
    if context.options.session.cookie_cache.enabled {
        cookies.extend(cookie_cache_cookies(context, session, user)?);
    }
    Ok(cookies)
}

fn cookie_cache_cookies(
    context: &AuthContext,
    session: &Session,
    user: &AnonymousUser,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let max_age = context
        .options
        .session
        .cookie_cache
        .max_age
        .unwrap_or(60 * 5);
    set_cookie_cache(
        &context.auth_cookies,
        &context.secret,
        &CookieCachePayload {
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
        },
        context.options.session.cookie_cache.strategy,
        max_age,
    )
}
