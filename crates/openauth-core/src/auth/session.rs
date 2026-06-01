//! Core session resolution and sign-out behavior.

use time::{Duration, OffsetDateTime};

use serde::Serialize;

use crate::context::AuthContext;
use crate::cookies::{
    delete_session_cookie, get_cookie_cache, get_session_cookie, parse_cookies, set_cookie_cache,
    set_session_cookie, verify_cookie_value, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions, SECURE_COOKIE_PREFIX,
};
use crate::db::{DbAdapter, Session, User};
use crate::error::OpenAuthError;
use crate::session::SessionStore;
use crate::user::DbUserStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSessionInput {
    pub cookie_header: String,
    pub disable_cookie_cache: bool,
    pub disable_refresh: bool,
    pub defer_refresh: bool,
}

impl GetSessionInput {
    pub fn new(cookie_header: impl Into<String>) -> Self {
        Self {
            cookie_header: cookie_header.into(),
            disable_cookie_cache: false,
            disable_refresh: false,
            defer_refresh: false,
        }
    }

    #[must_use]
    pub fn disable_cookie_cache(mut self) -> Self {
        self.disable_cookie_cache = true;
        self
    }

    #[must_use]
    pub fn disable_refresh(mut self) -> Self {
        self.disable_refresh = true;
        self
    }

    #[must_use]
    pub fn defer_refresh(mut self) -> Self {
        self.defer_refresh = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSessionResult {
    pub session: Option<Session>,
    pub user: Option<User>,
    pub cookies: Vec<Cookie>,
    pub needs_refresh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignOutResult {
    pub success: bool,
    #[serde(skip)]
    pub cookies: Vec<Cookie>,
}

#[derive(Clone, Copy)]
pub struct SessionAuth<'a> {
    adapter: &'a dyn DbAdapter,
    context: &'a AuthContext,
}

impl<'a> SessionAuth<'a> {
    pub fn new(adapter: &'a dyn DbAdapter, context: &'a AuthContext) -> Self {
        Self { adapter, context }
    }

    pub async fn get_session(
        &self,
        input: GetSessionInput,
    ) -> Result<Option<GetSessionResult>, OpenAuthError> {
        let signed_token = match get_session_cookie(
            &input.cookie_header,
            cookie_prefix(self.context),
            None,
            secure_cookies(self.context),
        ) {
            Some(value) => value,
            None => return Ok(None),
        };
        let Some(token) = verify_cookie_value(&signed_token, &self.context.secret)? else {
            return Ok(Some(unauthenticated(delete_session_cookie(
                &self.context.auth_cookies,
                &input.cookie_header,
                false,
            ))));
        };

        let session_store = SessionStore::new(self.adapter, self.context);
        if self.context.options.session.cookie_cache.enabled && !input.disable_cookie_cache {
            if let Some(cached) = get_cookie_cache::<Session, User>(
                &input.cookie_header,
                &self.context.auth_cookies.session_data.name,
                &self.context.secret,
                self.context.options.session.cookie_cache.strategy,
                self.context.options.session.cookie_cache.version.as_deref(),
            )? {
                if cached.session.token == token
                    && cached.session.expires_at > OffsetDateTime::now_utc()
                {
                    if session_store.find_session(&token).await?.is_none() {
                        return Ok(Some(unauthenticated(delete_session_cookie(
                            &self.context.auth_cookies,
                            &input.cookie_header,
                            false,
                        ))));
                    }
                    return Ok(Some(authenticated(
                        cached.session,
                        cached.user,
                        Vec::new(),
                        false,
                    )));
                }
            }
        }

        let Some(mut session) = session_store.find_session(&token).await? else {
            return Ok(Some(unauthenticated(delete_session_cookie(
                &self.context.auth_cookies,
                &input.cookie_header,
                false,
            ))));
        };

        let user_store = DbUserStore::new(self.adapter);
        let Some(user) = user_store.find_user_by_id(&session.user_id).await? else {
            return Ok(Some(unauthenticated(delete_session_cookie(
                &self.context.auth_cookies,
                &input.cookie_header,
                false,
            ))));
        };

        let dont_remember = signed_cookie(
            &input.cookie_header,
            &self.context.auth_cookies.dont_remember_token.name,
            &self.context.secret,
        )?
        .is_some();
        let needs_refresh = !dont_remember
            && !input.disable_refresh
            && !self.context.options.session.disable_session_refresh
            && session_needs_refresh(&session, self.context);
        let mut cookies = Vec::new();

        if needs_refresh && !input.defer_refresh {
            let refreshed_expires_at = OffsetDateTime::now_utc()
                + Duration::seconds(self.context.session_config.expires_in as i64);
            if let Some(updated_session) = session_store
                .update_session_expiry(&session.token, refreshed_expires_at)
                .await?
            {
                session = updated_session;
                cookies.extend(set_session_cookie(
                    &self.context.auth_cookies,
                    &self.context.secret,
                    &session.token,
                    SessionCookieOptions {
                        dont_remember: false,
                        overrides: CookieOptions {
                            max_age: seconds_until(session.expires_at),
                            ..CookieOptions::default()
                        },
                    },
                )?);
            } else {
                return Ok(Some(unauthenticated(delete_session_cookie(
                    &self.context.auth_cookies,
                    &input.cookie_header,
                    false,
                ))));
            }
        }

        if self.context.options.session.cookie_cache.enabled {
            cookies.extend(self.cookie_cache_cookies(&session, &user)?);
        }

        Ok(Some(authenticated(session, user, cookies, needs_refresh)))
    }

    pub async fn sign_out(
        &self,
        cookie_header: impl AsRef<str>,
    ) -> Result<SignOutResult, OpenAuthError> {
        let cookie_header = cookie_header.as_ref();
        if let Some(signed_token) = get_session_cookie(
            cookie_header,
            cookie_prefix(self.context),
            None,
            secure_cookies(self.context),
        ) {
            if let Some(token) = verify_cookie_value(&signed_token, &self.context.secret)? {
                SessionStore::new(self.adapter, self.context)
                    .delete_session(&token)
                    .await?;
            }
        }

        Ok(SignOutResult {
            success: true,
            cookies: delete_session_cookie(&self.context.auth_cookies, cookie_header, false),
        })
    }

    fn cookie_cache_cookies(
        &self,
        session: &Session,
        user: &User,
    ) -> Result<Vec<Cookie>, OpenAuthError> {
        let payload = CookieCachePayload {
            session: session.clone(),
            user: user.clone(),
            updated_at: OffsetDateTime::now_utc().unix_timestamp(),
            version: self
                .context
                .options
                .session
                .cookie_cache
                .version
                .clone()
                .unwrap_or_else(|| "1".to_owned()),
        };
        let max_age = self
            .context
            .options
            .session
            .cookie_cache
            .max_age
            .unwrap_or(60 * 5);
        set_cookie_cache(
            &self.context.auth_cookies,
            &self.context.secret,
            &payload,
            self.context.options.session.cookie_cache.strategy,
            max_age,
        )
    }
}

fn cookie_prefix(context: &AuthContext) -> Option<&str> {
    context.options.advanced.cookie_prefix.as_deref()
}

fn secure_cookies(context: &AuthContext) -> bool {
    context
        .auth_cookies
        .session_token
        .name
        .starts_with(SECURE_COOKIE_PREFIX)
}

fn signed_cookie(
    cookie_header: &str,
    cookie_name: &str,
    secret: &str,
) -> Result<Option<String>, OpenAuthError> {
    let Some(value) = parse_cookies(cookie_header).get(cookie_name).cloned() else {
        return Ok(None);
    };
    verify_cookie_value(&value, secret)
}

fn session_needs_refresh(session: &Session, context: &AuthContext) -> bool {
    if context.options.session.cookie_cache.refresh_cache {
        return false;
    }
    let due_at = session.expires_at - Duration::seconds(context.session_config.expires_in as i64)
        + Duration::seconds(context.session_config.update_age as i64);
    due_at <= OffsetDateTime::now_utc()
}

fn seconds_until(expires_at: OffsetDateTime) -> Option<u64> {
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    u64::try_from(seconds).ok()
}

fn authenticated(
    session: Session,
    user: User,
    cookies: Vec<Cookie>,
    needs_refresh: bool,
) -> GetSessionResult {
    GetSessionResult {
        session: Some(session),
        user: Some(user),
        cookies,
        needs_refresh,
    }
}

fn unauthenticated(cookies: Vec<Cookie>) -> GetSessionResult {
    GetSessionResult {
        session: None,
        user: None,
        cookies,
        needs_refresh: false,
    }
}
