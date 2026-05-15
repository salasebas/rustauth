use http::header;
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::context::request_state::current_new_session;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{AuthPlugin, PluginAfterHookAction};
use serde::Serialize;

use super::model::{self, AnonymousSession, LinkedSession};
use super::options::AnonymousOptions;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnonymousLinkAccount {
    pub anonymous_user: AnonymousSession,
    pub new_user: LinkedSession,
}

pub fn attach_link_hooks(mut plugin: AuthPlugin, options: AnonymousOptions) -> AuthPlugin {
    for path in [
        "/sign-in*",
        "/sign-up*",
        "/callback*",
        "/oauth2/callback*",
        "/magic-link/verify*",
        "/email-otp/verify-email*",
        "/one-tap/callback*",
        "/passkey/verify-authentication*",
        "/phone-number/verify*",
    ] {
        let options = options.clone();
        plugin = plugin.with_async_after_hook(path, move |context, request, response| {
            let options = options.clone();
            Box::pin(async move { link_after_hook(context, request, response, options).await })
        });
    }
    plugin
}

async fn link_after_hook(
    context: &AuthContext,
    request: &ApiRequest,
    response: ApiResponse,
    options: AnonymousOptions,
) -> Result<PluginAfterHookAction, OpenAuthError> {
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::Adapter("anonymous plugin requires a database adapter".to_owned())
    })?;
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(anonymous_user) = model::current_anonymous_session(
        adapter.as_ref(),
        context,
        options.storage_field_name(),
        cookie_header,
    )
    .await?
    else {
        return Ok(PluginAfterHookAction::Continue(response));
    };
    if !anonymous_user.user.is_anonymous {
        return Ok(PluginAfterHookAction::Continue(response));
    }

    let new_user = if let Some(new_user) =
        linked_session_from_request_state(adapter.as_ref(), &options).await?
    {
        new_user
    } else {
        let Some(new_session_token) = new_session_token(context, &response)? else {
            return Ok(PluginAfterHookAction::Continue(response));
        };
        let Some(new_user) = model::linked_session_from_token(
            adapter.as_ref(),
            options.storage_field_name(),
            &new_session_token,
        )
        .await?
        else {
            return Ok(PluginAfterHookAction::Continue(response));
        };
        new_user
    };

    finish_link(
        response,
        adapter.as_ref(),
        options,
        anonymous_user,
        new_user,
    )
    .await
}

async fn linked_session_from_request_state(
    adapter: &dyn openauth_core::db::DbAdapter,
    options: &AnonymousOptions,
) -> Result<Option<LinkedSession>, OpenAuthError> {
    let Some(new_session) = current_new_session_or_none()? else {
        return Ok(None);
    };
    let Some(user) =
        model::find_anonymous_user(adapter, options.storage_field_name(), &new_session.user.id)
            .await?
    else {
        return Ok(None);
    };
    Ok(Some(LinkedSession {
        session: new_session.session,
        user,
    }))
}

fn current_new_session_or_none(
) -> Result<Option<openauth_core::context::request_state::NewSession>, OpenAuthError> {
    match current_new_session() {
        Ok(session) => Ok(session),
        Err(OpenAuthError::RequestStateMissing) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn finish_link(
    response: ApiResponse,
    adapter: &dyn openauth_core::db::DbAdapter,
    options: AnonymousOptions,
    anonymous_user: AnonymousSession,
    new_user: LinkedSession,
) -> Result<PluginAfterHookAction, OpenAuthError> {
    if let Some(callback) = &options.on_link_account {
        callback(AnonymousLinkAccount {
            anonymous_user: anonymous_user.clone(),
            new_user: new_user.clone(),
        })
        .await?;
    }

    if options.disable_delete_anonymous_user
        || new_user.user.id == anonymous_user.user.id
        || new_user.user.is_anonymous
    {
        return Ok(PluginAfterHookAction::Continue(response));
    }

    model::delete_anonymous_user_records(adapter, &anonymous_user.user.id).await?;

    Ok(PluginAfterHookAction::Continue(response))
}

fn new_session_token(
    context: &AuthContext,
    response: &ApiResponse,
) -> Result<Option<String>, OpenAuthError> {
    for value in response.headers().get_all(header::SET_COOKIE) {
        let Ok(cookie) = value.to_str() else {
            continue;
        };
        let Some(raw_value) = cookie_value(cookie, &context.auth_cookies.session_token.name) else {
            continue;
        };
        if let Some(token) = model::verified_cookie_value(context, raw_value)? {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

fn cookie_value<'a>(set_cookie: &'a str, name: &str) -> Option<&'a str> {
    let (cookie_name, rest) = set_cookie.split_once('=')?;
    if cookie_name.trim() != name {
        return None;
    }
    Some(rest.split_once(';').map_or(rest, |(value, _)| value))
}
