use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::{
    body, config_id_matches, current_identity, endpoint, error, json, SharedConfigurations,
};
use crate::api_key::errors;
use crate::api_key::options::ApiKeyReference;
use crate::api_key::organization::{ensure_organization_permission, owns_user_key, ApiKeyAction};
use crate::api_key::storage::ApiKeyStore;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeleteApiKeyRequest {
    pub key_id: String,
    pub config_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DeleteApiKeyResponse {
    success: bool,
}

pub fn delete_endpoint(
    configurations: SharedConfigurations,
) -> openauth_core::api::AsyncAuthEndpoint {
    endpoint(
        "/api-key/delete",
        Method::POST,
        configurations,
        |context, request, configurations| {
            Box::pin(async move {
                let input: DeleteApiKeyRequest = body(&request)?;
                let options = configurations.resolve(input.config_id.as_deref())?;
                let Some(identity) = current_identity(context, &request).await? else {
                    return error(StatusCode::UNAUTHORIZED, errors::UNAUTHORIZED_SESSION);
                };
                let store = ApiKeyStore::new(context, &options);
                let Some(api_key) = store.get_by_id(&input.key_id).await? else {
                    return error(StatusCode::NOT_FOUND, errors::KEY_NOT_FOUND);
                };
                let expected_config_id = options.config_id.as_deref().unwrap_or("default");
                if !config_id_matches(&api_key.config_id, expected_config_id) {
                    return error(StatusCode::NOT_FOUND, errors::KEY_NOT_FOUND);
                }
                match options.reference {
                    ApiKeyReference::User
                        if owns_user_key(
                            options.reference,
                            &api_key.reference_id,
                            &identity.user.id,
                        ) => {}
                    ApiKeyReference::User => {
                        return error(StatusCode::NOT_FOUND, errors::KEY_NOT_FOUND)
                    }
                    ApiKeyReference::Organization => {
                        if let Err(error) = ensure_organization_permission(
                            context,
                            &identity.user.id,
                            &api_key.reference_id,
                            ApiKeyAction::Delete,
                        )
                        .await
                        {
                            return error_response_from_openauth(error);
                        }
                    }
                }
                store.delete(&api_key).await?;
                json(StatusCode::OK, &DeleteApiKeyResponse { success: true })
            })
        },
    )
}

fn error_response_from_openauth(
    error: openauth_core::error::OpenAuthError,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let message = error.to_string();
    if message.contains(errors::message(errors::USER_NOT_MEMBER_OF_ORGANIZATION)) {
        return super::error(
            StatusCode::FORBIDDEN,
            errors::USER_NOT_MEMBER_OF_ORGANIZATION,
        );
    }
    if message.contains(errors::message(errors::ORGANIZATION_PLUGIN_REQUIRED)) {
        return super::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            errors::ORGANIZATION_PLUGIN_REQUIRED,
        );
    }
    super::error(
        StatusCode::FORBIDDEN,
        errors::INSUFFICIENT_API_KEY_PERMISSIONS,
    )
}
