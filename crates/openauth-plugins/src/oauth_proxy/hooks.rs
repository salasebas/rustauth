use http::{header, HeaderValue};
use openauth_core::api::{ApiRequest, ApiResponse, PathParams};
use openauth_core::auth::oauth::{
    oauth_state_identifier, parse_oauth_state, set_token_util, OAuthAccountInput,
    OAuthBaseUrlOverride, OAuthStateData, OAuthUserInfo,
};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::options::OAuthStateStoreStrategy;
use openauth_core::plugin::{PluginAfterHookAction, PluginBeforeHookAction};
use openauth_core::plugin::{PluginAfterHookFuture, PluginBeforeHookFuture};
use openauth_core::verification::DbVerificationStore;
use openauth_oauth::oauth2::SocialAuthorizationCodeRequest;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use super::options::OAuthProxyOptions;
use super::payload::{OAuthProxyStatePackage, PassthroughPayload};
use super::utils::{
    decrypt, encrypt, production_base_url, proxy_callback_url, query_or_body_param, redirect_error,
    rewrite_callback_body, should_skip_proxy,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateCookiePackage {
    state: String,
    data: OAuthStateData,
}

pub(crate) fn before_sign_in(
    options: OAuthProxyOptions,
) -> impl for<'a> Fn(&'a AuthContext, ApiRequest) -> PluginBeforeHookFuture<'a> + Send + Sync + 'static
{
    move |context, mut request| {
        let options = options.clone();
        Box::pin(async move {
            if should_skip_proxy(context, &request, &options) {
                return Ok(PluginBeforeHookAction::Continue(request));
            }
            let original =
                original_callback_url(&request).unwrap_or_else(|| context.base_url.clone());
            let Some(proxy_url) = proxy_callback_url(context, &request, &options, &original) else {
                return Ok(PluginBeforeHookAction::Continue(request));
            };
            rewrite_callback_body(&mut request, &proxy_url)?;
            request
                .extensions_mut()
                .insert(OAuthBaseUrlOverride(production_base_url(context, &options)));
            Ok(PluginBeforeHookAction::Continue(request))
        })
    }
}

pub(crate) fn after_sign_in(
    options: OAuthProxyOptions,
) -> impl for<'a> Fn(&'a AuthContext, &'a ApiRequest, ApiResponse) -> PluginAfterHookFuture<'a>
       + Send
       + Sync
       + 'static {
    move |context, request, mut response| {
        let options = options.clone();
        Box::pin(async move {
            if should_skip_proxy(context, request, &options) {
                return Ok(PluginAfterHookAction::Continue(response));
            }
            let Some(location) = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
            else {
                return Ok(PluginAfterHookAction::Continue(response));
            };
            let Ok(mut provider_url) = Url::parse(&location) else {
                return Ok(PluginAfterHookAction::Continue(response));
            };
            let Some(state) = provider_url
                .query_pairs()
                .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            else {
                return Ok(PluginAfterHookAction::Continue(response));
            };
            let Some(state_data) = load_state_data(context, &state).await? else {
                return Ok(PluginAfterHookAction::Continue(response));
            };
            let state_cookie = encrypt(
                context,
                &options,
                &serde_json::to_string(&StateCookiePackage {
                    state: state.clone(),
                    data: state_data,
                })
                .map_err(json_error)?,
            )?;
            let package = OAuthProxyStatePackage {
                state,
                state_cookie,
                is_oauth_proxy: true,
            };
            let encrypted = encrypt(
                context,
                &options,
                &serde_json::to_string(&package).map_err(json_error)?,
            )?;
            provider_url.query_pairs_mut().clear().extend_pairs(
                Url::parse(&location)
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?
                    .query_pairs()
                    .map(|(key, value)| {
                        if key == "state" {
                            (key.into_owned(), encrypted.clone())
                        } else {
                            (key.into_owned(), value.into_owned())
                        }
                    }),
            );
            let next = provider_url.to_string();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&next)
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?,
            );
            if let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(response.body()) {
                if let Some(object) = body.as_object_mut() {
                    object.insert("url".to_owned(), serde_json::Value::String(next));
                    *response.body_mut() = serde_json::to_vec(&body)
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                }
            }
            Ok(PluginAfterHookAction::Continue(response))
        })
    }
}

pub(crate) fn before_callback(
    options: OAuthProxyOptions,
) -> impl for<'a> Fn(&'a AuthContext, ApiRequest) -> PluginBeforeHookFuture<'a> + Send + Sync + 'static
{
    move |context, request| {
        let options = options.clone();
        Box::pin(async move {
            let Some(state) = query_or_body_param(&request, "state") else {
                return Ok(PluginBeforeHookAction::Continue(request));
            };
            let package = match decrypt(context, &options, &state).and_then(|json| {
                serde_json::from_str::<OAuthProxyStatePackage>(&json).map_err(json_error)
            }) {
                Ok(package) if package.is_oauth_proxy => package,
                _ => return Ok(PluginBeforeHookAction::Continue(request)),
            };
            let state_cookie =
                match decrypt(context, &options, &package.state_cookie).and_then(|json| {
                    serde_json::from_str::<StateCookiePackage>(&json).map_err(json_error)
                }) {
                    Ok(state_cookie) => state_cookie,
                    Err(_) => {
                        return redirect_error(
                            &format!("{}/error", context.base_url.trim_end_matches('/')),
                            "invalid_state",
                        )
                        .map(PluginBeforeHookAction::Respond)
                    }
                };
            let error_url = state_cookie
                .data
                .error_url
                .clone()
                .unwrap_or_else(|| format!("{}/error", context.base_url.trim_end_matches('/')));
            if state_cookie.state != package.state {
                return redirect_error(&error_url, "state_mismatch")
                    .map(PluginBeforeHookAction::Respond);
            }
            let state_data = state_cookie.data;
            let error_url = state_data
                .error_url
                .clone()
                .unwrap_or_else(|| format!("{}/error", context.base_url.trim_end_matches('/')));
            if let Some(error) = query_or_body_param(&request, "error") {
                return redirect_error(&error_url, &error).map(PluginBeforeHookAction::Respond);
            }
            let Some(code) = query_or_body_param(&request, "code") else {
                return redirect_error(&error_url, "no_code").map(PluginBeforeHookAction::Respond);
            };
            let provider_id = request
                .extensions()
                .get::<PathParams>()
                .and_then(|params| params.get("id"))
                .ok_or_else(|| OpenAuthError::Api("missing path param `id`".to_owned()))?;
            let Some(provider) = context.social_provider(provider_id) else {
                return redirect_error(&error_url, "oauth_provider_not_found")
                    .map(PluginBeforeHookAction::Respond);
            };
            let tokens = match provider
                .validate_authorization_code(SocialAuthorizationCodeRequest {
                    code,
                    code_verifier: Some(state_data.code_verifier.clone()),
                    redirect_uri: format!(
                        "{}/callback/{}",
                        production_base_url(context, &options).trim_end_matches('/'),
                        provider.id()
                    ),
                    device_id: query_or_body_param(&request, "device_id"),
                })
                .await
            {
                Ok(tokens) => tokens,
                Err(_) => {
                    return redirect_error(&error_url, "invalid_code")
                        .map(PluginBeforeHookAction::Respond)
                }
            };
            let provider_user = query_or_body_param(&request, "user")
                .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok());
            let Some(user_info) = provider
                .get_user_info(tokens.clone(), provider_user)
                .await?
            else {
                return redirect_error(&error_url, "unable_to_get_user_info")
                    .map(PluginBeforeHookAction::Respond);
            };
            let Some(email) = user_info.email.clone() else {
                return redirect_error(&error_url, "email_not_found")
                    .map(PluginBeforeHookAction::Respond);
            };
            let proxy_url = Url::parse(&state_data.callback_url)
                .map_err(|error| OpenAuthError::Api(error.to_string()))?;
            let final_callback = proxy_url
                .query_pairs()
                .find_map(|(key, value)| (key == "callbackURL").then(|| value.into_owned()))
                .unwrap_or_else(|| state_data.callback_url.clone());
            let payload = PassthroughPayload {
                user_info: OAuthUserInfo {
                    id: user_info.id.clone(),
                    name: user_info.name.unwrap_or_default(),
                    email,
                    image: user_info.image,
                    email_verified: user_info.email_verified,
                    raw_attributes: None,
                },
                account: OAuthAccountInput {
                    provider_id: provider.id().to_owned(),
                    account_id: user_info.id,
                    access_token: set_token_util(tokens.access_token.as_deref(), context)?,
                    refresh_token: set_token_util(tokens.refresh_token.as_deref(), context)?,
                    id_token: tokens.id_token,
                    access_token_expires_at: tokens.access_token_expires_at,
                    refresh_token_expires_at: tokens.refresh_token_expires_at,
                    scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
                },
                state: package.state,
                callback_url: final_callback,
                new_user_url: state_data.new_user_url,
                error_url: state_data.error_url,
                disable_sign_up: (provider.provider_options().disable_implicit_sign_up
                    && !state_data.request_sign_up)
                    || provider.provider_options().disable_sign_up,
                timestamp: OffsetDateTime::now_utc().unix_timestamp(),
            };
            let encrypted = encrypt(
                context,
                &options,
                &serde_json::to_string(&payload).map_err(json_error)?,
            )?;
            let mut redirect_url = proxy_url;
            redirect_url
                .query_pairs_mut()
                .append_pair("profile", &encrypted);
            openauth_core::api::redirect_response(redirect_url.as_str(), Vec::new())
                .map(PluginBeforeHookAction::Respond)
        })
    }
}

pub(crate) fn after_callback(
    _options: OAuthProxyOptions,
) -> impl Fn(&AuthContext, &ApiRequest, ApiResponse) -> Result<PluginAfterHookAction, OpenAuthError>
       + Send
       + Sync
       + 'static {
    move |context, _request, mut response| {
        let Some(location) = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        else {
            return Ok(PluginAfterHookAction::Continue(response));
        };
        if !location.contains("/oauth-proxy-callback?callbackURL") {
            return Ok(PluginAfterHookAction::Continue(response));
        }
        let Ok(url) = Url::parse(&location) else {
            return Ok(PluginAfterHookAction::Continue(response));
        };
        let Ok(base) = Url::parse(&context.base_url) else {
            return Ok(PluginAfterHookAction::Continue(response));
        };
        if url.origin() == base.origin() {
            if let Some(callback) = url
                .query_pairs()
                .find_map(|(key, value)| (key == "callbackURL").then(|| value.into_owned()))
            {
                response.headers_mut().insert(
                    header::LOCATION,
                    HeaderValue::from_str(&callback)
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                );
            }
        }
        Ok(PluginAfterHookAction::Continue(response))
    }
}

async fn load_state_data(
    context: &AuthContext,
    state: &str,
) -> Result<Option<OAuthStateData>, OpenAuthError> {
    match context.options.account.store_state_strategy {
        OAuthStateStoreStrategy::Cookie => parse_oauth_state(context, None, state).await.map(Some),
        OAuthStateStoreStrategy::Database => {
            let Some(adapter) = context.adapter() else {
                return Ok(None);
            };
            let Some(verification) = DbVerificationStore::new(adapter.as_ref())
                .find_verification(&oauth_state_identifier(state))
                .await?
            else {
                return Ok(None);
            };
            serde_json::from_str::<OAuthStateData>(&verification.value)
                .map(Some)
                .map_err(json_error)
        }
    }
}

fn original_callback_url(request: &ApiRequest) -> Option<String> {
    if request.body().is_empty() {
        return None;
    }
    openauth_core::api::parse_request_body::<serde_json::Value>(request)
        .ok()
        .and_then(|body| {
            body.get("callbackURL")
                .or_else(|| body.get("callback_url"))
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
}

fn json_error(error: impl std::fmt::Display) -> OpenAuthError {
    OpenAuthError::Api(error.to_string())
}
