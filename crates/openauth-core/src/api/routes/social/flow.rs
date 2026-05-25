use http::StatusCode;
use serde_json::Value;
use std::sync::Arc;

use super::support::{
    body_string, oauth_user_info_error, path_param, percent_encode, redirect, redirect_uri,
    redirect_with_error, IdTokenBody, LinkStatusBody, SocialSessionBody,
};
use crate::api::{parse_request_body, request_base_url, ApiRequest, ApiResponse};
use crate::auth::oauth::{
    handle_oauth_user_info, HandleOAuthUserInfoInput, OAuthAccountInput, OAuthStateLink,
    OAuthUserInfo,
};
use crate::db::DbAdapter;
use crate::error::OpenAuthError;
use crate::user::{CreateOAuthAccountInput, DbUserStore};
use openauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, SocialAuthorizationCodeRequest, SocialIdTokenRequest,
    SocialOAuthProvider,
};

use super::super::shared::{
    auth_session_cookies, error_response, json_response, query_param, record_new_session,
};

pub(super) async fn sign_in_with_id_token(
    context: &crate::context::AuthContext,
    adapter: &dyn DbAdapter,
    provider: Arc<dyn SocialOAuthProvider>,
    id_token: IdTokenBody,
) -> Result<ApiResponse, OpenAuthError> {
    if !provider
        .verify_id_token(SocialIdTokenRequest {
            token: id_token.token.clone(),
            nonce: id_token.nonce.clone(),
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            scopes: id_token.scopes.clone(),
            provider_user: id_token.user.clone(),
        })
        .await?
    {
        return error_response(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token");
    }
    let tokens = tokens_from_id_token(&id_token);
    let Some(user_info) = provider
        .get_user_info(tokens.clone(), id_token.user.clone())
        .await?
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "FAILED_TO_GET_USER_INFO",
            "Failed to get user info",
        );
    };
    let result = handle_oauth_user_info(
        context,
        adapter,
        HandleOAuthUserInfoInput {
            user_info: normalize_user_info(&user_info)?,
            account: oauth_account(provider.id(), &user_info, &tokens, context)?,
            disable_sign_up: provider.provider_options().disable_sign_up,
            override_user_info: provider.provider_options().override_user_info_on_sign_in,
            is_trusted_provider: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    let Some(data) = result.data else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "OAUTH_LINK_ERROR",
            result
                .error
                .map_or("OAuth sign in failed".to_owned(), oauth_user_info_error),
        );
    };
    record_new_session(&data.session, &data.user)?;
    let cookies = auth_session_cookies(context, &data.session, &data.user, false)?;
    json_response(
        StatusCode::OK,
        &SocialSessionBody {
            redirect: false,
            token: data.session.token,
            url: None,
            user: data.user,
        },
        cookies,
    )
}

pub(super) async fn callback_get(
    context: &crate::context::AuthContext,
    adapter: &dyn DbAdapter,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let provider_id = path_param(&request, "id")?;
    let provider = lookup_provider(context, provider_id)?;
    let default_error_url = format!(
        "{}/error",
        request_base_url(context, Some(&request)).trim_end_matches('/')
    );
    let state = match query_param(&request, "state") {
        Some(state) => state,
        None => return redirect(&default_error_url, Vec::new()),
    };
    let state_data =
        match crate::auth::oauth::parse_oauth_state(context, Some(adapter), &state).await {
            Ok(data) => data,
            Err(_) => return redirect_with_error(&default_error_url, "invalid_state"),
        };
    let error_url = state_data.error_url.clone().unwrap_or(default_error_url);
    if let Some(error) = query_param(&request, "error") {
        return redirect_with_error(&error_url, &error);
    }
    let Some(code) = query_param(&request, "code") else {
        return redirect_with_error(&error_url, "no_code");
    };
    let tokens = match provider
        .validate_authorization_code(SocialAuthorizationCodeRequest {
            code,
            code_verifier: Some(state_data.code_verifier),
            redirect_uri: redirect_uri(context, &request, provider.id()),
            device_id: query_param(&request, "device_id"),
        })
        .await
    {
        Ok(tokens) => tokens,
        Err(_) => return redirect_with_error(&error_url, "invalid_code"),
    };
    let provider_user =
        query_param(&request, "user").and_then(|value| serde_json::from_str::<Value>(&value).ok());
    let Some(user_info) = provider
        .get_user_info(tokens.clone(), provider_user)
        .await?
    else {
        return redirect_with_error(&error_url, "unable_to_get_user_info");
    };
    if let Some(link) = state_data.link {
        link_oauth_account(
            context,
            adapter,
            provider.clone(),
            &link,
            &user_info,
            &tokens,
        )
        .await?;
        return redirect(&state_data.callback_url, Vec::new());
    }
    let result = handle_oauth_user_info(
        context,
        adapter,
        HandleOAuthUserInfoInput {
            user_info: normalize_user_info(&user_info)?,
            account: oauth_account(provider.id(), &user_info, &tokens, context)?,
            callback_url: Some(state_data.callback_url.clone()),
            disable_sign_up: (provider.provider_options().disable_implicit_sign_up
                && !state_data.request_sign_up)
                || provider.provider_options().disable_sign_up,
            override_user_info: provider.provider_options().override_user_info_on_sign_in,
            is_trusted_provider: true,
            require_trusted_provider_for_implicit_link: false,
        },
    )
    .await?;
    let Some(data) = result.data else {
        let error = result
            .error
            .map_or_else(|| "oauth_sign_in_failed".to_owned(), oauth_user_info_error);
        return redirect_with_error(&error_url, &error);
    };
    record_new_session(&data.session, &data.user)?;
    let cookies = auth_session_cookies(context, &data.session, &data.user, false)?;
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

pub(super) fn callback_post_redirect(
    context: &crate::context::AuthContext,
    request: &ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let provider_id = path_param(request, "id")?;
    let body = if request.body().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        parse_request_body::<Value>(request)?
    };
    let mut params = Vec::new();
    for key in [
        "code",
        "error",
        "device_id",
        "error_description",
        "state",
        "user",
    ] {
        if let Some(value) = query_param(request, key).or_else(|| body_string(&body, key)) {
            params.push(format!("{key}={}", percent_encode(&value)));
        }
    }
    let target = format!(
        "{}/callback/{provider_id}?{}",
        request_base_url(context, Some(request)).trim_end_matches('/'),
        params.join("&")
    );
    redirect(&target, Vec::new())
}

pub(super) async fn link_with_id_token(
    context: &crate::context::AuthContext,
    adapter: &dyn DbAdapter,
    provider: Arc<dyn SocialOAuthProvider>,
    user: &crate::db::User,
    id_token: IdTokenBody,
) -> Result<ApiResponse, OpenAuthError> {
    if !provider
        .verify_id_token(SocialIdTokenRequest {
            token: id_token.token.clone(),
            nonce: id_token.nonce.clone(),
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            scopes: id_token.scopes.clone(),
            provider_user: id_token.user.clone(),
        })
        .await?
    {
        return error_response(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token");
    }
    let tokens = tokens_from_id_token(&id_token);
    let Some(info) = provider
        .get_user_info(tokens.clone(), id_token.user)
        .await?
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "FAILED_TO_GET_USER_INFO",
            "Failed to get user info",
        );
    };
    let normalized = normalize_user_info(&info)?;
    if normalized.email.to_lowercase() != user.email.to_lowercase()
        && !context
            .options
            .account
            .account_linking
            .allow_different_emails
    {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
            "Account not linked - different emails not allowed",
        );
    }
    link_oauth_account(
        context,
        adapter,
        provider,
        &OAuthStateLink {
            user_id: user.id.clone(),
            email: user.email.clone(),
        },
        &info,
        &tokens,
    )
    .await?;
    json_response(
        StatusCode::OK,
        &LinkStatusBody {
            url: String::new(),
            redirect: false,
            status: true,
        },
        Vec::new(),
    )
}

async fn link_oauth_account(
    context: &crate::context::AuthContext,
    adapter: &dyn DbAdapter,
    provider: Arc<dyn SocialOAuthProvider>,
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
        return Err(OpenAuthError::Api(
            "OAuth account email does not match linked user".to_owned(),
        ));
    }
    let users = DbUserStore::new(adapter);
    if users
        .find_account_by_provider_account(&normalized.id, provider.id())
        .await?
        .is_some()
    {
        return Ok(());
    }
    users
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: provider.id().to_owned(),
            account_id: normalized.id,
            user_id: link.user_id.clone(),
            access_token: crate::auth::oauth::set_token_util(
                tokens.access_token.as_deref(),
                context,
            )?,
            refresh_token: crate::auth::oauth::set_token_util(
                tokens.refresh_token.as_deref(),
                context,
            )?,
            id_token: tokens.id_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
        })
        .await?;
    Ok(())
}

pub(super) fn lookup_provider(
    context: &crate::context::AuthContext,
    provider_id: &str,
) -> Result<Arc<dyn SocialOAuthProvider>, OpenAuthError> {
    context
        .social_provider(provider_id)
        .ok_or_else(|| OpenAuthError::Api(format!("social provider `{provider_id}` was not found")))
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
        raw_attributes: None,
    })
}

fn oauth_account(
    provider_id: &str,
    info: &OAuth2UserInfo,
    tokens: &OAuth2Tokens,
    context: &crate::context::AuthContext,
) -> Result<OAuthAccountInput, OpenAuthError> {
    Ok(OAuthAccountInput {
        provider_id: provider_id.to_owned(),
        account_id: info.id.clone(),
        access_token: crate::auth::oauth::set_token_util(tokens.access_token.as_deref(), context)?,
        refresh_token: crate::auth::oauth::set_token_util(
            tokens.refresh_token.as_deref(),
            context,
        )?,
        id_token: tokens.id_token.clone(),
        access_token_expires_at: tokens.access_token_expires_at,
        refresh_token_expires_at: tokens.refresh_token_expires_at,
        scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
    })
}

fn tokens_from_id_token(id_token: &IdTokenBody) -> OAuth2Tokens {
    OAuth2Tokens {
        access_token: id_token.access_token.clone(),
        refresh_token: id_token.refresh_token.clone(),
        id_token: Some(id_token.token.clone()),
        scopes: id_token.scopes.clone(),
        ..OAuth2Tokens::default()
    }
}
