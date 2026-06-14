use http::{Method, StatusCode};
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, redirect_openapi_response, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpointOptions, OpenApiOperation,
};
use rustauth_core::auth::oauth::{
    generate_oauth_state, handle_oauth_user_info, parse_oauth_state_with_input,
    HandleOAuthUserInfoInput, OAuthStateInput, OAuthStateLink, OAuthStateParseInput,
};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{parse_cookies, set_session_cookie, Cookie, SessionCookieOptions};
use rustauth_core::error::RustAuthError;
use rustauth_oauth::oauth2::{
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
    let options = std::sync::Arc::new(options);
    let discovery_cache = std::sync::Arc::new(discovery_cache);
    create_auth_endpoint(
        "/sign-in/oauth2",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInWithOAuth2")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_in_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            let discovery_cache = std::sync::Arc::clone(&discovery_cache);
            async move {
                let adapter = context.require_adapter()?;
                let body: SignInOAuth2Body = parse_request_body(&request)?;
                if options.find(&body.provider_id).is_none() {
                    let message = format!("No config found for provider {}", body.provider_id);
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        errors::PROVIDER_CONFIG_NOT_FOUND,
                        &message,
                    );
                }
                let mut config =
                    match resolved_config(&options, &discovery_cache, &body.provider_id).await {
                        Ok(config) => config,
                        Err(error) => return config_error_response(error),
                    };
                let redirect_uri = callback_redirect_uri(&context, &config);
                resolve_authorization_url_params(
                    &mut config,
                    GenericOAuthFlow::SignIn,
                    redirect_uri.clone(),
                )
                .await?;
                let state = generate_oauth_state(
                    &context,
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
                let provider = GenericOAuthProvider::with_discovery_cache(
                    config.clone(),
                    (*discovery_cache).clone(),
                );
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri,
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: None,
                })?;
                redirect_json_response(
                    url.to_string(),
                    !body.disable_redirect,
                    vec![oauth_state_cookie(&context, &state.data.oauth_state)],
                )
            }
        },
    )
}

pub fn oauth2_callback_endpoint(
    options: GenericOAuthOptions,
    discovery_cache: DiscoveryCache,
) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    let discovery_cache = std::sync::Arc::new(discovery_cache);
    create_auth_endpoint(
        "/oauth2/callback/:providerId",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("oAuth2Callback")
            .openapi(
                OpenApiOperation::new("oAuth2Callback")
                    .description("Handle generic OAuth2 callback")
                    .response("302", redirect_openapi_response("OAuth callback redirect")),
            ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            let discovery_cache = std::sync::Arc::clone(&discovery_cache);
            async move {
                callback_get(
                    &context,
                    options.as_ref(),
                    discovery_cache.as_ref(),
                    request,
                )
                .await
            }
        },
    )
}

pub fn oauth2_link_endpoint(
    options: GenericOAuthOptions,
    discovery_cache: DiscoveryCache,
) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    let discovery_cache = std::sync::Arc::new(discovery_cache);
    create_auth_endpoint(
        "/oauth2/link",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("oAuth2LinkAccount")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(link_schema()),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            let discovery_cache = std::sync::Arc::clone(&discovery_cache);
            async move {
                let adapter = context.require_adapter()?;
                let Some((_session, user)) = current_session(&context, &request).await? else {
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
                let redirect_uri = callback_redirect_uri(&context, &config);
                resolve_authorization_url_params(
                    &mut config,
                    GenericOAuthFlow::Link,
                    redirect_uri.clone(),
                )
                .await?;
                let state = generate_oauth_state(
                    &context,
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
                let provider = GenericOAuthProvider::with_discovery_cache(
                    config.clone(),
                    (*discovery_cache).clone(),
                );
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri,
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: None,
                })?;
                redirect_json_response(
                    url.to_string(),
                    true,
                    vec![oauth_state_cookie(&context, &state.data.oauth_state)],
                )
            }
        },
    )
}

async fn callback_get(
    context: &AuthContext,
    options: &GenericOAuthOptions,
    discovery_cache: &DiscoveryCache,
    request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    let adapter = context.require_adapter()?;
    let provider_id = path_param(&request, "providerId")?;
    let mut config = match resolved_config(options, discovery_cache, provider_id).await {
        Ok(config) => config,
        Err(error) => {
            return redirect_with_error(
                &default_error_url(context),
                callback_config_error_code(&error),
            );
        }
    };
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
    let oauth_state = oauth_state_cookie_value(context, &request);
    let state_data = match parse_oauth_state_with_input(
        context,
        Some(adapter.as_ref()),
        OAuthStateParseInput {
            state: &state,
            oauth_state: oauth_state.as_deref(),
            skip_state_cookie_check: context.options.account.skip_state_cookie_check,
        },
    )
    .await
    {
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
        if let Err(error) = link_account(context, &config, &link, &user_info, &tokens).await {
            return redirect_with_error(&error_url, link_error_code(&error));
        }
        return redirect(&state_data.callback_url, Vec::new());
    }
    let user_info = match normalize_user_info(&user_info) {
        Ok(user_info) => user_info,
        Err(_) => return redirect_with_error(&error_url, "user_info_is_missing"),
    };
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
            is_trusted_provider: false,
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

fn oauth_state_cookie(context: &AuthContext, oauth_state: &str) -> Cookie {
    Cookie {
        name: context.auth_cookies.oauth_state.name.clone(),
        value: oauth_state.to_owned(),
        attributes: context.auth_cookies.oauth_state.attributes.clone(),
    }
}

fn oauth_state_cookie_value(context: &AuthContext, request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| {
            parse_cookies(header)
                .get(&context.auth_cookies.oauth_state.name)
                .cloned()
        })
}

fn callback_config_error_code(error: &RustAuthError) -> &'static str {
    match error {
        RustAuthError::Api(code) if code == errors::PROVIDER_CONFIG_NOT_FOUND => {
            "provider_config_not_found"
        }
        RustAuthError::Api(code) if code == errors::PROVIDER_ID_REQUIRED => "provider_id_required",
        RustAuthError::Api(code) if code == errors::TOKEN_URL_NOT_FOUND => "token_url_not_found",
        RustAuthError::Api(code) if code == errors::ISSUER_MISSING => "issuer_missing",
        RustAuthError::Api(code) if code == errors::INVALID_OAUTH_CONFIG => "invalid_oauth_config",
        _ => "invalid_oauth_configuration",
    }
}
