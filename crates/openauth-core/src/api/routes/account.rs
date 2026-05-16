use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::shared::{
    current_session, error_response, json_response, status_openapi_response, unauthorized,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::oauth::{decrypt_oauth_token, set_token_util};
use crate::db::{Account, DbAdapter};
use crate::error::OpenAuthError;
use crate::user::{DbUserStore, UpdateAccountInput};
use openauth_oauth::oauth2::{OAuth2Tokens, OAuth2UserInfo};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlinkAccountBody {
    provider_id: String,
    account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenBody {
    provider_id: String,
    account_id: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountResponse {
    id: String,
    provider_id: String,
    account_id: String,
    user_id: String,
    scopes: Vec<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    status: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessTokenResponse {
    access_token: Option<String>,
    access_token_expires_at: Option<OffsetDateTime>,
    scopes: Vec<String>,
    id_token: Option<String>,
    token_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshTokenResponse {
    access_token: String,
    refresh_token: String,
    access_token_expires_at: Option<OffsetDateTime>,
    refresh_token_expires_at: Option<OffsetDateTime>,
    scope: Option<String>,
    id_token: Option<String>,
    provider_id: String,
    account_id: String,
    token_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountInfoResponse {
    user: AccountInfoUser,
    data: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountInfoUser {
    id: String,
    name: Option<String>,
    email: Option<String>,
    image: Option<String>,
    email_verified: bool,
}

pub(super) fn list_user_accounts_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
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
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let accounts = DbUserStore::new(adapter.as_ref())
                    .list_accounts_for_user(&user.id)
                    .await?
                    .into_iter()
                    .map(AccountResponse::from)
                    .collect::<Vec<_>>();

                json_response(StatusCode::OK, &accounts, cookies)
            })
        },
    )
}

pub(super) fn get_access_token_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
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
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let body: TokenBody = parse_request_body(&request)?;
                let Some((_, session_user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let requested_user_id = body.user_id.as_deref().unwrap_or(&session_user.id);
                if requested_user_id != session_user.id {
                    return unauthorized();
                }
                let users = DbUserStore::new(adapter.as_ref());
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
                        let decrypted = decrypt_oauth_token(&refresh_token, context)?;
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
                                    context,
                                    &users,
                                    account,
                                    tokens.clone(),
                                    None,
                                )
                                .await?;
                                return json_response(
                                    StatusCode::OK,
                                    &access_token_response_from_tokens(tokens, &account),
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
                            .map(|token| decrypt_oauth_token(token, context))
                            .transpose()?,
                        access_token_expires_at: account.access_token_expires_at,
                        scopes: account_scopes(&account),
                        id_token: account.id_token.clone(),
                        token_type: None,
                    },
                    cookies,
                )
            })
        },
    )
}

pub(super) fn refresh_token_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
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
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let body: TokenBody = parse_request_body(&request)?;
                let Some((_, session_user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
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
                let users = DbUserStore::new(adapter.as_ref());
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
                let decrypted = decrypt_oauth_token(refresh_token, context)?;
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
                    context,
                    &users,
                    account,
                    tokens.clone(),
                    Some(&decrypted),
                )
                .await?;
                json_response(
                    StatusCode::OK,
                    &RefreshTokenResponse {
                        access_token: tokens.access_token.unwrap_or_default(),
                        refresh_token: tokens.refresh_token.unwrap_or_else(|| decrypted.to_owned()),
                        access_token_expires_at: updated_account.access_token_expires_at,
                        refresh_token_expires_at: updated_account.refresh_token_expires_at,
                        scope: updated_account.scope.clone(),
                        id_token: updated_account.id_token.clone(),
                        provider_id: updated_account.provider_id,
                        account_id: updated_account.account_id,
                        token_type: tokens.token_type,
                    },
                    cookies,
                )
            })
        },
    )
}

pub(super) fn account_info_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
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
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, session_user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let account_id = super::shared::query_param(&request, "accountId");
                let users = DbUserStore::new(adapter.as_ref());
                let accounts = users.list_accounts_for_user(&session_user.id).await?;
                let account = match account_id.as_deref() {
                    Some(account_id) => accounts.into_iter().find(|account| {
                        account.account_id == account_id || account.id == account_id
                    }),
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
                            let decrypted = decrypt_oauth_token(&refresh_token, context)?;
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
                                        context,
                                        &users,
                                        account,
                                        tokens.clone(),
                                        None,
                                    )
                                    .await?;
                                    tokens
                                }
                                Err(error) if is_refresh_unsupported(&error) => {
                                    tokens_from_account(context, &account)?
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
                        None => tokens_from_account(context, &account)?,
                    }
                } else {
                    tokens_from_account(context, &account)?
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
            })
        },
    )
}

pub(super) fn unlink_account_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
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
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: UnlinkAccountBody = parse_request_body(&request)?;
                let users = DbUserStore::new(adapter.as_ref());
                let accounts = users.list_accounts_for_user(&user.id).await?;
                if accounts.len() == 1 {
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
            })
        },
    )
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        Self {
            id: account.id,
            provider_id: account.provider_id,
            account_id: account.account_id,
            user_id: account.user_id,
            scopes: account
                .scope
                .map(|scope| {
                    scope
                        .split(',')
                        .filter(|scope| !scope.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

fn unlink_account_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String)
            .description("The provider ID of the account to unlink"),
        BodyField::optional("accountId", JsonSchemaType::String)
            .description("The account ID to unlink"),
    ])
}

fn token_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String)
            .description("The provider ID for the OAuth provider"),
        BodyField::optional("accountId", JsonSchemaType::String)
            .description("The account ID associated with the refresh token"),
        BodyField::optional("userId", JsonSchemaType::String)
            .description("The user ID associated with the account"),
    ])
}

fn account_openapi_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "providerId": { "type": "string" },
            "accountId": { "type": "string" },
            "userId": { "type": "string" },
            "scopes": {
                "type": "array",
                "items": { "type": "string" },
            },
            "createdAt": { "type": "string", "format": "date-time" },
            "updatedAt": { "type": "string", "format": "date-time" },
        },
        "required": [
            "id",
            "providerId",
            "accountId",
            "userId",
            "scopes",
            "createdAt",
            "updatedAt"
        ],
    })
}

fn token_openapi_response(include_refresh: bool) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    properties.insert("tokenType".to_owned(), json!({ "type": "string" }));
    properties.insert("idToken".to_owned(), json!({ "type": "string" }));
    properties.insert("accessToken".to_owned(), json!({ "type": "string" }));
    properties.insert(
        "accessTokenExpiresAt".to_owned(),
        json!({ "type": "string", "format": "date-time" }),
    );
    if include_refresh {
        properties.insert("refreshToken".to_owned(), json!({ "type": "string" }));
        properties.insert(
            "refreshTokenExpiresAt".to_owned(),
            json!({ "type": "string", "format": "date-time" }),
        );
    }
    super::shared::json_openapi_response(
        "Success",
        Value::Object(
            [
                ("type".to_owned(), json!("object")),
                ("properties".to_owned(), Value::Object(properties)),
            ]
            .into_iter()
            .collect(),
        ),
    )
}

async fn find_user_account(
    users: &DbUserStore<'_>,
    user_id: &str,
    provider_id: &str,
    account_id: Option<&str>,
) -> Result<Option<Account>, OpenAuthError> {
    let accounts = users.list_accounts_for_user(user_id).await?;
    Ok(accounts.into_iter().find(|account| {
        account.provider_id == provider_id
            && account_id
                .map(|account_id| account.account_id == account_id)
                .unwrap_or(true)
    }))
}

fn should_refresh(account: &Account) -> bool {
    account
        .access_token_expires_at
        .map(|expires_at| expires_at - OffsetDateTime::now_utc() < time::Duration::seconds(5))
        .unwrap_or(false)
}

async fn persist_refreshed_tokens(
    context: &crate::context::AuthContext,
    users: &DbUserStore<'_>,
    account: Account,
    tokens: OAuth2Tokens,
    fallback_refresh_token: Option<&str>,
) -> Result<Account, OpenAuthError> {
    let access_token = match tokens.access_token.as_deref() {
        Some(token) => set_token_util(Some(token), context)?,
        None => account.access_token.clone(),
    };
    let refresh_token = match tokens.refresh_token.as_deref().or(fallback_refresh_token) {
        Some(token) => set_token_util(Some(token), context)?,
        None => account.refresh_token.clone(),
    };
    let id_token = tokens.id_token.clone().or_else(|| account.id_token.clone());
    let access_token_expires_at = tokens
        .access_token_expires_at
        .or(account.access_token_expires_at);
    let refresh_token_expires_at = tokens
        .refresh_token_expires_at
        .or(account.refresh_token_expires_at);
    let scope = if tokens.scopes.is_empty() {
        account.scope.clone()
    } else {
        Some(tokens.scopes.join(","))
    };
    users
        .update_account(
            &account.id,
            UpdateAccountInput {
                access_token: Some(access_token),
                refresh_token: Some(refresh_token),
                id_token: Some(id_token),
                access_token_expires_at: Some(access_token_expires_at),
                refresh_token_expires_at: Some(refresh_token_expires_at),
                scope: Some(scope),
            },
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("failed to update account".to_owned()))
}

fn access_token_response_from_tokens(
    tokens: OAuth2Tokens,
    account: &Account,
) -> AccessTokenResponse {
    AccessTokenResponse {
        access_token: tokens.access_token,
        access_token_expires_at: tokens
            .access_token_expires_at
            .or(account.access_token_expires_at),
        scopes: if tokens.scopes.is_empty() {
            account_scopes(account)
        } else {
            tokens.scopes
        },
        id_token: tokens.id_token.or_else(|| account.id_token.clone()),
        token_type: tokens.token_type,
    }
}

fn tokens_from_account(
    context: &crate::context::AuthContext,
    account: &Account,
) -> Result<OAuth2Tokens, OpenAuthError> {
    Ok(OAuth2Tokens {
        access_token: account
            .access_token
            .as_deref()
            .map(|token| decrypt_oauth_token(token, context))
            .transpose()?,
        refresh_token: account
            .refresh_token
            .as_deref()
            .map(|token| decrypt_oauth_token(token, context))
            .transpose()?,
        access_token_expires_at: account.access_token_expires_at,
        refresh_token_expires_at: account.refresh_token_expires_at,
        scopes: account_scopes(account),
        id_token: account.id_token.clone(),
        ..OAuth2Tokens::default()
    })
}

fn account_scopes(account: &Account) -> Vec<String> {
    account
        .scope
        .as_deref()
        .map(|scope| {
            scope
                .split(',')
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn is_refresh_unsupported(error: &openauth_oauth::oauth2::OAuthError) -> bool {
    error
        .to_string()
        .contains("does not support refresh tokens")
}

fn provider_not_supported(provider_id: &str) -> Result<crate::api::ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "PROVIDER_NOT_SUPPORTED",
        format!("Provider {provider_id} is not supported."),
    )
}

fn account_not_found() -> Result<crate::api::ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "ACCOUNT_NOT_FOUND",
        "Account not found",
    )
}

impl From<OAuth2UserInfo> for AccountInfoUser {
    fn from(user: OAuth2UserInfo) -> Self {
        Self {
            id: user.id,
            name: user.name,
            email: user.email,
            image: user.image,
            email_verified: user.email_verified,
        }
    }
}
