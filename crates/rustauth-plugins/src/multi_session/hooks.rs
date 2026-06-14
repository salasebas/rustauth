use super::cookies::{
    append_cookies, expire_multi_cookie_name, multi_cookie_name, multi_session_cookie,
    signed_multi_tokens,
};
use super::options::MultiSessionOptions;
use rustauth_core::context::request_state::current_new_session;
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::PluginAfterHookAction;

pub fn store_multi_session_cookie(
    config: MultiSessionOptions,
) -> impl for<'a> Fn(
    &'a AuthContext,
    &'a rustauth_core::api::ApiRequest,
    rustauth_core::api::ApiResponse,
) -> rustauth_core::plugin::PluginAfterHookFuture<'a>
       + Send
       + Sync
       + 'static {
    move |context, request, response| {
        Box::pin(async move {
            store_multi_session_cookie_inner(context, request, response, config).await
        })
    }
}

pub fn revoke_multi_session_cookies() -> impl for<'a> Fn(
    &'a AuthContext,
    &'a rustauth_core::api::ApiRequest,
    rustauth_core::api::ApiResponse,
) -> rustauth_core::plugin::PluginAfterHookFuture<'a>
       + Send
       + Sync
       + 'static {
    move |context, request, response| {
        Box::pin(
            async move { revoke_multi_session_cookies_inner(context, request, response).await },
        )
    }
}

async fn store_multi_session_cookie_inner(
    context: &AuthContext,
    request: &rustauth_core::api::ApiRequest,
    mut response: rustauth_core::api::ApiResponse,
    config: MultiSessionOptions,
) -> Result<PluginAfterHookAction, RustAuthError> {
    let Some(created) = current_new_session()? else {
        return Ok(PluginAfterHookAction::Continue(response));
    };
    let cookie_header = request_cookie_header(request);
    let cookie_name = multi_cookie_name(context, &created.session.token);
    if response_has_cookie(&response, &cookie_name)
        || request_has_cookie(&cookie_header, &cookie_name)
    {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    if context.adapter().is_none() {
        return Ok(PluginAfterHookAction::Continue(response));
    }

    let current_signed_count = signed_multi_tokens(context, &cookie_header)?.len();
    let deleted =
        delete_same_user_sessions(context, &cookie_header, &created.user.id, &mut response).await?;
    let current_count = current_signed_count.saturating_sub(deleted) + 1;
    if current_count > config.maximum_sessions {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    append_cookies(
        &mut response,
        [multi_session_cookie(context, &created.session.token)?],
    )?;
    Ok(PluginAfterHookAction::Continue(response))
}

async fn revoke_multi_session_cookies_inner(
    context: &AuthContext,
    request: &rustauth_core::api::ApiRequest,
    mut response: rustauth_core::api::ApiResponse,
) -> Result<PluginAfterHookAction, RustAuthError> {
    if context.adapter().is_none() {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    let cookie_header = request_cookie_header(request);
    let tokens = signed_multi_tokens(context, &cookie_header)?;
    for (key, token) in &tokens {
        append_cookies(&mut response, [expire_multi_cookie_name(context, key)])?;
        context.sessions()?.delete_session(token).await?;
    }
    Ok(PluginAfterHookAction::Continue(response))
}

async fn delete_same_user_sessions(
    context: &AuthContext,
    cookie_header: &str,
    user_id: &str,
    response: &mut rustauth_core::api::ApiResponse,
) -> Result<usize, RustAuthError> {
    let mut deleted = 0;
    for (key, token) in signed_multi_tokens(context, cookie_header)? {
        let Some(session) = context.sessions()?.find_session(&token).await? else {
            continue;
        };
        if session.user_id != user_id {
            continue;
        }
        context.sessions()?.delete_session(&token).await?;
        append_cookies(response, [expire_multi_cookie_name(context, &key)])?;
        deleted += 1;
    }
    Ok(deleted)
}

fn request_cookie_header(request: &rustauth_core::api::ApiRequest) -> String {
    request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn request_has_cookie(cookie_header: &str, name: &str) -> bool {
    rustauth_core::cookies::parse_cookies(cookie_header).contains_key(name)
}

fn response_has_cookie(response: &rustauth_core::api::ApiResponse, name: &str) -> bool {
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|cookie| cookie.starts_with(&format!("{name}=")))
}
