use http::Method;
use rustauth_core::api::{
    create_auth_endpoint, redirect_response, session_cookies, ApiRequest, AsyncAuthEndpoint,
    AuthEndpointOptions, OpenApiOperation,
};
use rustauth_core::auth::oauth::{
    handle_oauth_user_info, parse_oauth_state_with_input, HandleOAuthUserInfoInput,
    OAuthStateParseInput,
};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::OAuthStateStoreStrategy;
use time::OffsetDateTime;

use super::options::OAuthProxyOptions;
use super::payload::PassthroughPayload;
use super::utils::{decrypt, is_trusted_callback_url, query_param, redirect_error};

pub(crate) fn oauth_proxy_callback_endpoint(options: OAuthProxyOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth-proxy-callback",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("oauthProxyCallback")
            .openapi(
                OpenApiOperation::new("oauthProxyCallback").description("OAuth Proxy Callback"),
            ),
        move |context, request| {
            let options = options.clone();
            async move { handle_callback(&context, request, &options).await }
        },
    )
}

async fn handle_callback(
    context: &rustauth_core::context::AuthContext,
    request: ApiRequest,
    options: &OAuthProxyOptions,
) -> Result<rustauth_core::api::ApiResponse, RustAuthError> {
    let default_error_url = format!("{}/error", context.base_url.trim_end_matches('/'));
    let Some(callback_url) = query_param(&request, "callbackURL") else {
        return redirect_error(&default_error_url, "missing_callback_url");
    };
    if !is_trusted_callback_url(context, &request, &callback_url)? {
        return redirect_error(&default_error_url, "invalid_callback_url");
    }
    let Some(encrypted_profile) = query_param(&request, "profile") else {
        return redirect_error(&default_error_url, "missing_profile");
    };
    let decrypted = match decrypt(context, options, &encrypted_profile) {
        Ok(value) => value,
        Err(_) => return redirect_error(&default_error_url, "invalid_profile"),
    };
    let payload = match serde_json::from_str::<PassthroughPayload>(&decrypted) {
        Ok(value) if value.has_required_fields() => value,
        _ => return redirect_error(&default_error_url, "invalid_payload"),
    };
    let error_url = payload.error_url.as_deref().unwrap_or(&default_error_url);
    let age = OffsetDateTime::now_utc().unix_timestamp() - payload.timestamp;
    if age > options.max_age.whole_seconds() || age < -10 {
        return redirect_error(error_url, "payload_expired");
    }
    let adapter = match context.require_adapter() {
        Ok(adapter) => adapter,
        Err(_) => return redirect_error(error_url, "user_creation_failed"),
    };
    if !context.options.account.skip_state_cookie_check {
        match context.options.account.store_state_strategy {
            OAuthStateStoreStrategy::Cookie => {
                if parse_oauth_state_with_input(
                    context,
                    None,
                    OAuthStateParseInput {
                        state: &payload.state,
                        oauth_state: payload.oauth_state.as_deref(),
                        skip_state_cookie_check: false,
                    },
                )
                .await
                .is_err()
                {
                    return redirect_error(error_url, "invalid_state");
                }
            }
            OAuthStateStoreStrategy::Database => {
                if payload.oauth_state.as_deref().map_or(true, str::is_empty) {
                    return redirect_error(error_url, "invalid_state");
                }
            }
        }
    }
    let trusted_provider = is_trusted_provider(context, &payload.account.provider_id);
    let result = handle_oauth_user_info(
        context,
        adapter.as_ref(),
        HandleOAuthUserInfoInput {
            user_info: payload.user_info,
            account: payload.account,
            callback_url: Some(payload.callback_url.clone()),
            disable_sign_up: payload.disable_sign_up,
            override_user_info: false,
            is_trusted_provider: trusted_provider,
            require_trusted_provider_for_implicit_link: false,
        },
    )
    .await?;
    let Some(data) = result.data else {
        return redirect_error(error_url, "user_creation_failed");
    };
    let cookies = session_cookies(context, &data.session, &data.user, false)?;
    let final_url = if result.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
    } else {
        &payload.callback_url
    };
    redirect_response(final_url, cookies)
}

fn is_trusted_provider(context: &rustauth_core::context::AuthContext, provider_id: &str) -> bool {
    context
        .options
        .account
        .account_linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == provider_id)
}
