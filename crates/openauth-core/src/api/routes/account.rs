use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::shared::{
    current_session, error_response, json_response, status_openapi_response, unauthorized,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::db::{Account, DbAdapter};
use crate::user::DbUserStore;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlinkAccountBody {
    provider_id: String,
    account_id: Option<String>,
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
