use http::{header, HeaderValue, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiRequest, ApiResponse, AsyncAuthEndpoint,
    AuthEndpointOptions, PathParams,
};
use openauth_core::auth::oauth::{
    generate_oauth_state, handle_oauth_user_info, parse_oauth_state, set_token_util,
    HandleOAuthUserInfoInput, OAuthAccountInput, OAuthStateInput, OAuthStateLink, OAuthUserInfo,
};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    get_session_cookie, set_session_cookie, verify_cookie_value, SessionCookieOptions,
};
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::session::DbSessionStore;
use openauth_core::user::{CreateOAuthAccountInput, DbUserStore};
use openauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, SocialAuthorizationCodeRequest, SocialAuthorizationUrlRequest,
    SocialOAuthProvider,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

use super::config::{GenericOAuthConfig, GenericOAuthOptions};
use super::errors;
use super::provider::GenericOAuthProvider;
use super::route_http::{
    api_error, json_response, link_schema, redirect, redirect_with_error, sign_in_schema,
};

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

#[derive(Debug, Serialize)]
struct RedirectBody {
    url: String,
    redirect: bool,
}

pub fn sign_in_oauth2_endpoint(options: GenericOAuthOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/oauth2",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInWithOAuth2")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_in_schema()),
        move |context, request| {
            let options = options.clone();
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
                let config = resolved_config(&options, &body.provider_id).await?;
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
                let provider = GenericOAuthProvider::new(config.clone());
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri: oauth2_redirect_uri(context, &config.provider_id),
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: None,
                })?;
                redirect_json_response(url.to_string(), !body.disable_redirect)
            })
        },
    )
}

pub fn oauth2_callback_endpoint(options: GenericOAuthOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/callback/:providerId",
        Method::GET,
        AuthEndpointOptions::new().operation_id("oAuth2Callback"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move { callback_get(context, &options, request).await })
        },
    )
}

pub fn oauth2_link_endpoint(options: GenericOAuthOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/link",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("oAuth2LinkAccount")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(link_schema()),
        move |context, request| {
            let options = options.clone();
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
                let config = resolved_config(&options, &body.provider_id).await?;
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
                let provider = GenericOAuthProvider::new(config.clone());
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri: oauth2_redirect_uri(context, &config.provider_id),
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
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let adapter = adapter(context)?;
    let provider_id = path_param(&request, "providerId")?;
    let config = resolved_config(options, provider_id).await?;
    if let Some(error) = query_param(&request, "error") {
        return redirect_with_error(&default_error_url(context), &error);
    }
    let Some(code) = query_param(&request, "code") else {
        return redirect_with_error(&default_error_url(context), "oAuth_code_missing");
    };
    validate_issuer(&config, query_param(&request, "iss").as_deref())?;
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
    let provider = GenericOAuthProvider::new(config.clone());
    let tokens = match provider
        .validate_authorization_code(SocialAuthorizationCodeRequest {
            code,
            code_verifier: Some(state_data.code_verifier),
            redirect_uri: oauth2_redirect_uri(context, &config.provider_id),
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
        link_account(
            context,
            adapter.as_ref(),
            &config,
            &link,
            &user_info,
            &tokens,
        )
        .await?;
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
        },
    )
    .await?;
    let Some(data) = result.data else {
        return redirect_with_error(&error_url, "oauth_sign_in_failed");
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

async fn resolved_config(
    options: &GenericOAuthOptions,
    provider_id: &str,
) -> Result<GenericOAuthConfig, OpenAuthError> {
    let mut config = options
        .find(provider_id)
        .cloned()
        .ok_or_else(|| api_error_value(errors::PROVIDER_CONFIG_NOT_FOUND))?;
    if let Some(discovery) = super::discovery::fetch(&config).await? {
        config.authorization_url = config
            .authorization_url
            .or(discovery.authorization_endpoint);
        config.token_url = config.token_url.or(discovery.token_endpoint);
        config.user_info_url = config.user_info_url.or(discovery.userinfo_endpoint);
        config.issuer = config.issuer.or(discovery.issuer);
    }
    if config.authorization_url.is_none() || config.token_url.is_none() {
        return Err(api_error_value(errors::INVALID_OAUTH_CONFIGURATION));
    }
    Ok(config)
}

fn validate_issuer(
    config: &GenericOAuthConfig,
    received: Option<&str>,
) -> Result<(), OpenAuthError> {
    let Some(expected) = config.issuer.as_deref() else {
        return Ok(());
    };
    match received {
        Some(received) if received == expected => Ok(()),
        Some(_) => Err(api_error_value(errors::ISSUER_MISMATCH)),
        None if config.require_issuer_validation => Err(api_error_value(errors::ISSUER_MISSING)),
        None => Ok(()),
    }
}

fn adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("generic-oauth routes require an adapter".to_owned())
    })
}

async fn current_session(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    request: &ApiRequest,
) -> Result<Option<(openauth_core::db::Session, openauth_core::db::User)>, OpenAuthError> {
    let Some(cookie_header) = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let Some(signed_token) = get_session_cookie(cookie_header, None, None) else {
        return Ok(None);
    };
    let Some(token) = verify_cookie_value(&signed_token, &context.secret)? else {
        return Ok(None);
    };
    let Some(session) = DbSessionStore::new(adapter).find_session(&token).await? else {
        return Ok(None);
    };
    let Some(user) = DbUserStore::new(adapter)
        .find_user_by_id(&session.user_id)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some((session, user)))
}

async fn link_account(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    config: &GenericOAuthConfig,
    link: &OAuthStateLink,
    info: &OAuth2UserInfo,
    tokens: &OAuth2Tokens,
) -> Result<(), OpenAuthError> {
    let normalized = normalize_user_info(info)?;
    if normalized.email.to_lowercase() != link.email.to_lowercase()
        && !context
            .options
            .account
            .account_linking
            .allow_different_emails
    {
        return Err(OpenAuthError::Api("email_doesn't_match".to_owned()));
    }
    DbUserStore::new(adapter)
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: config.provider_id.clone(),
            account_id: normalized.id,
            user_id: link.user_id.clone(),
            access_token: set_token_util(tokens.access_token.as_deref(), context)?,
            refresh_token: set_token_util(tokens.refresh_token.as_deref(), context)?,
            id_token: tokens.id_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
        })
        .await?;
    Ok(())
}

fn oauth_account(
    context: &AuthContext,
    provider_id: &str,
    account_id: &str,
    tokens: &OAuth2Tokens,
) -> Result<OAuthAccountInput, OpenAuthError> {
    Ok(OAuthAccountInput {
        provider_id: provider_id.to_owned(),
        account_id: account_id.to_owned(),
        access_token: set_token_util(tokens.access_token.as_deref(), context)?,
        refresh_token: set_token_util(tokens.refresh_token.as_deref(), context)?,
        id_token: tokens.id_token.clone(),
        access_token_expires_at: tokens.access_token_expires_at,
        refresh_token_expires_at: tokens.refresh_token_expires_at,
        scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
    })
}

fn normalize_user_info(info: &OAuth2UserInfo) -> Result<OAuthUserInfo, OpenAuthError> {
    let email = info
        .email
        .clone()
        .ok_or_else(|| OpenAuthError::Api("OAuth provider did not return an email".to_owned()))?;
    Ok(OAuthUserInfo {
        id: info.id.clone(),
        name: info.name.clone().unwrap_or_default(),
        email,
        image: info.image.clone(),
        email_verified: info.email_verified,
    })
}

fn path_param<'a>(request: &'a ApiRequest, name: &str) -> Result<&'a str, OpenAuthError> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .ok_or_else(|| OpenAuthError::Api(format!("missing path param `{name}`")))
}

fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    })
}

fn oauth2_redirect_uri(context: &AuthContext, provider_id: &str) -> String {
    format!(
        "{}/oauth2/callback/{provider_id}",
        context.base_url.trim_end_matches('/')
    )
}

fn default_error_url(context: &AuthContext) -> String {
    format!("{}/error", context.base_url.trim_end_matches('/'))
}

fn redirect_json_response(url: String, redirect: bool) -> Result<ApiResponse, OpenAuthError> {
    let mut response = json_response(
        StatusCode::OK,
        &RedirectBody {
            url: url.clone(),
            redirect,
        },
    )?;
    if redirect {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&url).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        );
    }
    Ok(response)
}

fn api_error_value(code: &str) -> OpenAuthError {
    OpenAuthError::Api(code.to_owned())
}
