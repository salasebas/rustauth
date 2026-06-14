use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, SessionCookieOptions,
};
use rustauth_core::db::Session;
use rustauth_core::error::RustAuthError;
use time::OffsetDateTime;

use super::model::AnonymousUser;

pub fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &AnonymousUser,
) -> Result<Vec<Cookie>, RustAuthError> {
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
) -> Result<Vec<Cookie>, RustAuthError> {
    let max_age = context
        .options
        .session
        .cookie_cache
        .max_age
        .unwrap_or(time::Duration::minutes(5));
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
        max_age.whole_seconds() as u64,
    )
}
