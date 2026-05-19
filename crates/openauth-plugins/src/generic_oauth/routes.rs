use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiRequest, ApiResponse, AsyncAuthEndpoint,
    AuthEndpointOptions,
};
use openauth_core::auth::oauth::{
    generate_oauth_state, handle_oauth_user_info, parse_oauth_state, HandleOAuthUserInfoInput,
    OAuthStateInput, OAuthStateLink,
};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{set_session_cookie, SessionCookieOptions};
use openauth_core::error::OpenAuthError;
use openauth_oauth::oauth2::{
    SocialAuthorizationCodeRequest, SocialAuthorizationUrlRequest, SocialOAuthProvider,
};
use serde::Deserialize;
use serde_json::Value;

use super::account::{link_account, link_error_code, normalize_user_info, oauth_account};
use super::config::{GenericOAuthFlow, GenericOAuthOptions};
use super::discovery::DiscoveryCache;
use super::errors;
use super::provider::GenericOAuthProvider;
use super::route_http::{
    api_error, link_schema, redirect, redirect_with_error, redirect_with_error_description,
    sign_in_schema,
};
use super::route_support::*;

#[derive(Debug, Deserialize)]
struct SignInOAuth2Body {
    #[serde(alias = "providerId")]
    provider_id: String,
    #[serde(default, alias = "callbackURL")]
    callback_url: Option<String>,
    #[serde(default, alias = "errorCallbackURL")]
    error_callback_url: Option<String>,
    #[serde(default, alias = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(default, alias = "disableRedirect")]
    disable_redirect: bool,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default, alias = "requestSignUp")]
    request_sign_up: bool,
    #[serde(default, alias = "additionalData")]
    additional_data: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct LinkOAuth2Body {
    #[serde(alias = "providerId")]
    provider_id: String,
    #[serde(alias = "callbackURL")]
    callback_url: String,
    #[serde(default, alias = "errorCallbackURL")]
    error_callback_url: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

pub fn sign_in_oauth2_endpoint(
    options: GenericOAuthOptions,
    discovery_cache: DiscoveryCache,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/oauth2",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInWithOAuth2")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_in_schema()),
        move |context, request| {
            let options = options.clone();
            let discovery_cache = discovery_cache.clone();
            Box::pin(async move {
                let adapter = adapter(context)?;
                let body: SignInOAuth2Body = parse_request_body(&request)?;
                if options.find(&body.provider_id).is_none() {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        errors::PROVIDER_CONFIG_NOT_FOUND,
                        "No config found for provider",
                    );
                }
                let mut config =
                    match resolved_config(&options, &discovery_cache, &body.provider_id).await {
                        Ok(config) => config,
                        Err(error) => return config_error_response(error),
                    };
                let redirect_uri = callback_redirect_uri(context, &config);
                resolve_authorization_url_params(
                    &mut config,
                    GenericOAuthFlow::SignIn,
                    redirect_uri.clone(),
                )
                .await?;
                let state = generate_oauth_state(
                    context,
                    Some(adapter.as_ref()),
                    OAuthStateInput {
                        callback_url: body.callback_url.unwrap_or_else(|| "/".to_owned()),
                        error_url: body.error_callback_url,
                        new_user_url: body.new_user_callback_url,
                        request_sign_up: body.request_sign_up,
                        additional_data: body.additional_data.unwrap_or(Value::Null),
                        ..OAuthStateInput::default()
                    },
                )
                .await?;
                let provider =
                    GenericOAuthProvider::with_discovery_cache(config.clone(), discovery_cache);
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri,
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: None,
                })?;
                redirect_json_response(url.to_string(), !body.disable_redirect)
            })
        },
    )
}

pub fn oauth2_callback_endpoint(
    options: GenericOAuthOptions,
    discovery_cache: DiscoveryCache,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/callback/:providerId",
        Method::GET,
        AuthEndpointOptions::new().operation_id("oAuth2Callback"),
        move |context, request| {
            let options = options.clone();
            let discovery_cache = discovery_cache.clone();
            Box::pin(
                async move { callback_get(context, &options, &discovery_cache, request).await },
            )
        },
    )
}

pub fn oauth2_link_endpoint(
    options: GenericOAuthOptions,
    discovery_cache: DiscoveryCache,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/link",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("oAuth2LinkAccount")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(link_schema()),
        move |context, request| {
            let options = options.clone();
            let discovery_cache = discovery_cache.clone();
            Box::pin(async move {
                let adapter = adapter(context)?;
                let Some((_session, user)) =
                    current_session(context, adapter.as_ref(), &request).await?
                else {
                    return api_error(
                        StatusCode::UNAUTHORIZED,
                        errors::SESSION_REQUIRED,
                        "Session is required",
                    );
                };
                let body: LinkOAuth2Body = parse_request_body(&request)?;
                if options.find(&body.provider_id).is_none() {
                    return api_error(
                        StatusCode::NOT_FOUND,
                        errors::PROVIDER_CONFIG_NOT_FOUND,
                        "No config found for provider",
                    );
                }
                let mut config =
                    match resolved_config(&options, &discovery_cache, &body.provider_id).await {
                        Ok(config) => config,
                        Err(error) => return config_error_response(error),
                    };
                let redirect_uri = callback_redirect_uri(context, &config);
                resolve_authorization_url_params(
                    &mut config,
                    GenericOAuthFlow::Link,
                    redirect_uri.clone(),
                )
                .await?;
                let state = generate_oauth_state(
                    context,
                    Some(adapter.as_ref()),
                    OAuthStateInput {
                        callback_url: body.callback_url,
                        error_url: body.error_callback_url,
                        link: Some(OAuthStateLink {
                            user_id: user.id,
                            email: user.email,
                        }),
                        ..OAuthStateInput::default()
                    },
                )
                .await?;
                let provider =
                    GenericOAuthProvider::with_discovery_cache(config.clone(), discovery_cache);
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri,
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: None,
                })?;
                redirect_json_response(url.to_string(), true)
            })
        },
    )
}

async fn callback_get(
    context: &AuthContext,
    options: &GenericOAuthOptions,
    discovery_cache: &DiscoveryCache,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let adapter = adapter(context)?;
    let provider_id = path_param(&request, "providerId")?;
    let mut config = resolved_config(options, discovery_cache, provider_id).await?;
    if let Some(error) = query_param(&request, "error") {
        return redirect_with_error_description(
            &default_error_url(context),
            &error,
            query_param(&request, "error_description").as_deref(),
        );
    }
    let Some(code) = query_param(&request, "code") else {
        return redirect_with_error(&default_error_url(context), "oAuth_code_missing");
    };
    let Some(state) = query_param(&request, "state") else {
        return redirect_with_error(&default_error_url(context), "invalid_state");
    };
    let state_data = match parse_oauth_state(context, Some(adapter.as_ref()), &state).await {
        Ok(data) => data,
        Err(_) => return redirect_with_error(&default_error_url(context), "invalid_state"),
    };
    let error_url = state_data
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url(context));
    if let Some(error) = issuer_error(&config, query_param(&request, "iss").as_deref()) {
        return redirect_with_error(&error_url, error);
    }
    let redirect_uri = callback_redirect_uri(context, &config);
    if resolve_token_url_params(
        &mut config,
        GenericOAuthFlow::Callback,
        redirect_uri.clone(),
    )
    .await
    .is_err()
    {
        return redirect_with_error(&error_url, "oauth_code_verification_failed");
    }
    let provider =
        GenericOAuthProvider::with_discovery_cache(config.clone(), discovery_cache.clone());
    let tokens = match provider
        .validate_authorization_code(SocialAuthorizationCodeRequest {
            code,
            code_verifier: Some(state_data.code_verifier),
            redirect_uri,
            device_id: query_param(&request, "device_id"),
        })
        .await
    {
        Ok(tokens) => tokens,
        Err(_) => return redirect_with_error(&error_url, "oauth_code_verification_failed"),
    };
    let Some(user_info) = provider.get_user_info(tokens.clone(), None).await? else {
        return redirect_with_error(&error_url, "user_info_is_missing");
    };
    if let Some(link) = state_data.link {
        if let Err(error) = link_account(
            context,
            adapter.as_ref(),
            &config,
            &link,
            &user_info,
            &tokens,
        )
        .await
        {
            return redirect_with_error(&error_url, link_error_code(&error));
        }
        return redirect(&state_data.callback_url, Vec::new());
    }
    let user_info = normalize_user_info(&user_info)?;
    let result = handle_oauth_user_info(
        context,
        adapter.as_ref(),
        HandleOAuthUserInfoInput {
            account: oauth_account(context, &config.provider_id, &user_info.id, &tokens)?,
            user_info,
            callback_url: Some(state_data.callback_url.clone()),
            disable_sign_up: (config.disable_implicit_sign_up && !state_data.request_sign_up)
                || config.disable_sign_up,
            override_user_info: config.override_user_info,
            is_trusted_provider: true,
            require_trusted_provider_for_implicit_link: false,
        },
    )
    .await?;
    let Some(data) = result.data else {
        return redirect_with_error(
            &error_url,
            result
                .error
                .map(oauth_user_info_error)
                .unwrap_or("oauth_sign_in_failed"),
        );
    };
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &data.session.token,
        SessionCookieOptions::default(),
    )?;
    cookies.extend(result.cookies);
    let target = if result.is_register {
        state_data
            .new_user_url
            .as_deref()
            .unwrap_or(&state_data.callback_url)
    } else {
        &state_data.callback_url
    };
    redirect(target, cookies)
}
