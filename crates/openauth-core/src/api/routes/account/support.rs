use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::super::shared::{error_response, json_openapi_response};
use crate::api::{ApiResponse, BodyField, BodySchema, JsonSchemaType};
use crate::auth::oauth::{decrypt_oauth_token, set_token_util};
use crate::db::Account;
use crate::error::OpenAuthError;
use crate::user::{DbUserStore, UpdateAccountInput};
use openauth_oauth::oauth2::{OAuth2Tokens, OAuth2UserInfo};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnlinkAccountBody {
    pub(super) provider_id: String,
    pub(super) account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenBody {
    pub(super) provider_id: String,
    pub(super) account_id: Option<String>,
    pub(super) user_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccountResponse {
    id: String,
    provider_id: String,
    account_id: String,
    user_id: String,
    scopes: Vec<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct StatusBody {
    pub(super) status: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccessTokenResponse {
    pub(super) access_token: Option<String>,
    pub(super) access_token_expires_at: Option<OffsetDateTime>,
    pub(super) scopes: Vec<String>,
    pub(super) id_token: Option<String>,
    pub(super) token_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RefreshTokenResponse {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    pub(super) access_token_expires_at: Option<OffsetDateTime>,
    pub(super) refresh_token_expires_at: Option<OffsetDateTime>,
    pub(super) scope: Option<String>,
    pub(super) id_token: Option<String>,
    pub(super) provider_id: String,
    pub(super) account_id: String,
    pub(super) token_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccountInfoResponse {
    pub(super) user: AccountInfoUser,
    pub(super) data: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccountInfoUser {
    id: String,
    name: Option<String>,
    email: Option<String>,
    image: Option<String>,
    email_verified: bool,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        let scopes = account_scopes(&account);
        Self {
            id: account.id,
            provider_id: account.provider_id,
            account_id: account.account_id,
            user_id: account.user_id,
            scopes,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
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

pub(super) fn unlink_account_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String)
            .description("The provider ID of the account to unlink"),
        BodyField::optional("accountId", JsonSchemaType::String)
            .description("The account ID to unlink"),
    ])
}

pub(super) fn token_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String)
            .description("The provider ID for the OAuth provider"),
        BodyField::optional("accountId", JsonSchemaType::String)
            .description("The account ID associated with the refresh token"),
        BodyField::optional("userId", JsonSchemaType::String)
            .description("The user ID associated with the account"),
    ])
}

pub(super) fn account_openapi_schema() -> serde_json::Value {
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

pub(super) fn token_openapi_response(include_refresh: bool) -> serde_json::Value {
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
    json_openapi_response(
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

pub(super) async fn find_user_account(
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

pub(super) fn should_refresh(account: &Account) -> bool {
    account
        .access_token_expires_at
        .map(|expires_at| expires_at - OffsetDateTime::now_utc() < time::Duration::seconds(5))
        .unwrap_or(false)
}

pub(super) async fn persist_refreshed_tokens(
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

pub(super) fn access_token_response_from_tokens(
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

pub(super) fn tokens_from_account(
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

pub(super) fn is_refresh_unsupported(error: &openauth_oauth::oauth2::OAuthError) -> bool {
    error
        .to_string()
        .contains("does not support refresh tokens")
}

pub(super) fn provider_not_supported(provider_id: &str) -> Result<ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "PROVIDER_NOT_SUPPORTED",
        format!("Provider {provider_id} is not supported."),
    )
}

pub(super) fn account_not_found() -> Result<ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "ACCOUNT_NOT_FOUND",
        "Account not found",
    )
}

pub(super) fn account_scopes(account: &Account) -> Vec<String> {
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
