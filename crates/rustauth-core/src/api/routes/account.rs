mod support;

use http::{Method, StatusCode};
#[cfg(feature = "oauth")]
use serde_json::json;

use super::shared::{
    error_response, json_response, sensitive_session, status_openapi_response, unauthorized,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
#[cfg(feature = "oauth")]
use crate::auth::oauth::{decrypt_oauth_token, decrypt_optional_oauth_token};

#[cfg(feature = "oauth")]
use support::{
    access_token_response_from_tokens, account_cookie, account_not_found, account_scopes,
    find_user_account, is_refresh_unsupported, persist_refreshed_tokens, provider_not_supported,
    should_refresh, token_body_schema, token_openapi_response, tokens_from_account,
    AccessTokenResponse, AccountInfoResponse, RefreshTokenResponse, TokenBody,
};
use support::{
    account_openapi_schema, unlink_account_body_schema, AccountResponse, StatusBody,
    UnlinkAccountBody,
};

pub(super) fn list_user_accounts_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/list-accounts",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("listUserAccounts")
            .openapi(
                OpenApiOperation::new("listUserAccounts")
                    .description("List all accounts linked to the user")
                    .response(
                        "200",
                        super::shared::json_openapi_response(
                            "Success",
                            serde_json::json!({
                                "type": "array",
                                "items": account_openapi_schema(),
                            }),
                        ),
                    ),
            ),
        move |context, request| async move {
            let Some((_, user, cookies)) = sensitive_session(&context, &request).await? else {
                return unauthorized();
            };
            let accounts = context
                .users()?
                .list_accounts_for_user(&user.id)
                .await?
                .into_iter()
                .map(AccountResponse::from)
                .collect::<Vec<_>>();

            json_response(StatusCode::OK, &accounts, cookies)
        },
    )
}

#[cfg(feature = "oauth")]
pub(super) fn get_access_token_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/get-access-token",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("getAccessToken")
            .body_schema(token_body_schema())
            .openapi(
                OpenApiOperation::new("getAccessToken")
                    .description("Get a valid access token, doing a refresh if needed")
                    .response("200", token_openapi_response(false)),
            ),
        move |context, request| async move {
            let body: TokenBody = parse_request_body(&request)?;
            let Some((_, session_user, mut cookies)) =
                sensitive_session(&context, &request).await?
            else {
                return unauthorized();
            };
            let requested_user_id = body.user_id.as_deref().unwrap_or(&session_user.id);
            if requested_user_id != session_user.id {
                return unauthorized();
            }
            let users = context.users()?;
            let Some(mut account) = find_user_account(
                &users,
                &session_user.id,
                &body.provider_id,
                body.account_id.as_deref(),
            )
            .await?
            else {
                return account_not_found();
            };
            let Some(provider) = context.social_provider(&body.provider_id) else {
                return provider_not_supported(&body.provider_id);
            };
            if should_refresh(&account) {
                if let Some(refresh_token) = account.refresh_token.clone() {
                    let decrypted = decrypt_oauth_token(&refresh_token, &context)?;
                    match provider.refresh_access_token(decrypted).await {
                        Ok(tokens) => {
                            if tokens.access_token.is_none() {
                                return error_response(
                                    StatusCode::BAD_REQUEST,
                                    "FAILED_TO_GET_ACCESS_TOKEN",
                                    "Failed to get a valid access token",
                                );
                            }
                            account = persist_refreshed_tokens(
                                &context,
                                &users,
                                account,
                                tokens.clone(),
                                None,
                            )
                            .await?;
                            cookies.extend(account_cookie(&context, &account)?);
                            return json_response(
                                StatusCode::OK,
                                &access_token_response_from_tokens(&context, tokens, &account)?,
                                cookies,
                            );
                        }
                        Err(error) if is_refresh_unsupported(&error) => {}
                        Err(_) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "FAILED_TO_GET_ACCESS_TOKEN",
                                "Failed to get a valid access token",
                            );
                        }
                    }
                }
            }
            json_response(
                StatusCode::OK,
                &AccessTokenResponse {
                    access_token: account
                        .access_token
                        .as_deref()
                        .map(|token| decrypt_oauth_token(token, &context))
                        .transpose()?,
                    access_token_expires_at: account.access_token_expires_at,
                    scopes: account_scopes(&account),
                    id_token: decrypt_optional_oauth_token(account.id_token.as_deref(), &context)?,
                    token_type: None,
                },
                cookies,
            )
        },
    )
}

#[cfg(feature = "oauth")]
pub(super) fn refresh_token_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/refresh-token",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("refreshToken")
            .body_schema(token_body_schema())
            .openapi(
                OpenApiOperation::new("refreshToken")
                    .description("Refresh the access token using a refresh token")
                    .response("200", token_openapi_response(true)),
            ),
        move |context, request| async move {
            let body: TokenBody = parse_request_body(&request)?;
            let Some((_, session_user, mut cookies)) =
                sensitive_session(&context, &request).await?
            else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "USER_ID_OR_SESSION_REQUIRED",
                    "Either userId or session is required",
                );
            };
            let requested_user_id = body.user_id.as_deref().unwrap_or(&session_user.id);
            if requested_user_id != session_user.id {
                return unauthorized();
            }
            let Some(provider) = context.social_provider(&body.provider_id) else {
                return provider_not_supported(&body.provider_id);
            };
            let users = context.users()?;
            let Some(account) = find_user_account(
                &users,
                &session_user.id,
                &body.provider_id,
                body.account_id.as_deref(),
            )
            .await?
            else {
                return account_not_found();
            };
            let Some(refresh_token) = account.refresh_token.as_deref() else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "REFRESH_TOKEN_NOT_FOUND",
                    "Refresh token not found",
                );
            };
            let decrypted = decrypt_oauth_token(refresh_token, &context)?;
            let tokens = match provider.refresh_access_token(decrypted.clone()).await {
                Ok(tokens) => tokens,
                Err(error) if is_refresh_unsupported(&error) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "TOKEN_REFRESH_NOT_SUPPORTED",
                        format!(
                            "Provider {} does not support token refreshing.",
                            body.provider_id
                        ),
                    );
                }
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "FAILED_TO_REFRESH_ACCESS_TOKEN",
                        "Failed to refresh access token",
                    );
                }
            };
            if tokens.access_token.is_none() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "FAILED_TO_REFRESH_ACCESS_TOKEN",
                    "Failed to refresh access token",
                );
            }
            let updated_account = persist_refreshed_tokens(
                &context,
                &users,
                account,
                tokens.clone(),
                Some(&decrypted),
            )
            .await?;
            cookies.extend(account_cookie(&context, &updated_account)?);
            json_response(
                StatusCode::OK,
                &RefreshTokenResponse {
                    access_token: tokens.access_token.unwrap_or_default(),
                    refresh_token: tokens.refresh_token.unwrap_or_else(|| decrypted.to_owned()),
                    access_token_expires_at: updated_account.access_token_expires_at,
                    refresh_token_expires_at: updated_account.refresh_token_expires_at,
                    scope: updated_account.scope.clone(),
                    id_token: decrypt_optional_oauth_token(
                        updated_account.id_token.as_deref(),
                        &context,
                    )?,
                    provider_id: updated_account.provider_id,
                    account_id: updated_account.account_id,
                    token_type: tokens.token_type,
                },
                cookies,
            )
        },
    )
}

#[cfg(feature = "oauth")]
pub(super) fn account_info_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/account-info",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("accountInfo")
            .openapi(
                OpenApiOperation::new("accountInfo")
                    .description("Get the account info provided by the provider")
                    .response(
                        "200",
                        super::shared::json_openapi_response(
                            "Success",
                            json!({
                                "type": "object",
                                "properties": {
                                    "user": { "type": "object" },
                                    "data": { "type": "object", "additionalProperties": true },
                                },
                                "required": ["user", "data"],
                            }),
                        ),
                    ),
            ),
        move |context, request| async move {
            let Some((_, session_user, mut cookies)) =
                sensitive_session(&context, &request).await?
            else {
                return unauthorized();
            };
            let account_id = super::shared::query_param(&request, "accountId");
            let users = context.users()?;
            let accounts = users.list_accounts_for_user(&session_user.id).await?;
            let account = match account_id.as_deref() {
                Some(account_id) => accounts
                    .into_iter()
                    .find(|account| account.account_id == account_id || account.id == account_id),
                None => accounts
                    .into_iter()
                    .find(|account| account.provider_id != "credential"),
            };
            let Some(account) = account else {
                return account_not_found();
            };
            let Some(provider) = context.social_provider(&account.provider_id) else {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "PROVIDER_NOT_CONFIGURED",
                    format!(
                        "Provider account provider is {} but it is not configured",
                        account.provider_id
                    ),
                );
            };
            let mut account = account;
            let tokens = if should_refresh(&account) {
                match account.refresh_token.clone() {
                    Some(refresh_token) => {
                        let decrypted = decrypt_oauth_token(&refresh_token, &context)?;
                        match provider.refresh_access_token(decrypted).await {
                            Ok(tokens) => {
                                if tokens.access_token.is_none() {
                                    return error_response(
                                        StatusCode::BAD_REQUEST,
                                        "FAILED_TO_GET_ACCESS_TOKEN",
                                        "Failed to get a valid access token",
                                    );
                                }
                                account = persist_refreshed_tokens(
                                    &context,
                                    &users,
                                    account,
                                    tokens.clone(),
                                    None,
                                )
                                .await?;
                                cookies.extend(account_cookie(&context, &account)?);
                                tokens
                            }
                            Err(error) if is_refresh_unsupported(&error) => {
                                tokens_from_account(&context, &account)?
                            }
                            Err(_) => {
                                return error_response(
                                    StatusCode::BAD_REQUEST,
                                    "FAILED_TO_GET_ACCESS_TOKEN",
                                    "Failed to get a valid access token",
                                );
                            }
                        }
                    }
                    None => tokens_from_account(&context, &account)?,
                }
            } else {
                tokens_from_account(&context, &account)?
            };
            let Some(user_info) = provider.get_user_info(tokens, None).await? else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "ACCESS_TOKEN_NOT_FOUND",
                    "Access token not found",
                );
            };
            json_response(
                StatusCode::OK,
                &AccountInfoResponse {
                    user: user_info.into(),
                    data: json!({ "provider": account.provider_id }),
                },
                cookies,
            )
        },
    )
}

pub(super) fn unlink_account_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/unlink-account",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("unlinkAccount")
            .body_schema(unlink_account_body_schema())
            .openapi(
                OpenApiOperation::new("unlinkAccount")
                    .description("Unlink an account")
                    .response("200", status_openapi_response("Success")),
            ),
        move |context, request| async move {
            let Some((_, user, cookies)) = sensitive_session(&context, &request).await? else {
                return unauthorized();
            };
            let body: UnlinkAccountBody = parse_request_body(&request)?;
            let users = context.users()?;
            let accounts = users.list_accounts_for_user(&user.id).await?;
            if accounts.len() == 1 && !context.options.account.account_linking.allow_unlinking_all {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "FAILED_TO_UNLINK_LAST_ACCOUNT",
                    "Failed to unlink last account",
                );
            }

            let Some(account) = accounts.iter().find(|account| {
                account.provider_id == body.provider_id
                    && match body.account_id.as_ref() {
                        Some(account_id) => account.account_id == *account_id,
                        None => true,
                    }
            }) else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "ACCOUNT_NOT_FOUND",
                    "Account not found",
                );
            };

            users.delete_account(&account.id).await?;
            json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
        },
    )
}
