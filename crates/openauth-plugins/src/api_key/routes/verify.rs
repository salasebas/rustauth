use http::{Method, StatusCode};
use openauth_core::context::AuthContext;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{body, endpoint, json, SharedConfigurations};
use crate::api_key::cleanup;
use crate::api_key::errors;
use crate::api_key::hashing::default_key_hasher;
use crate::api_key::models::{ApiKeyPublicRecord, ApiKeyRecord};
use crate::api_key::options::{ApiKeyConfiguration, ApiKeyPermissions};
use crate::api_key::permissions;
use crate::api_key::rate_limit;
use crate::api_key::storage::ApiKeyStore;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerifyApiKeyRequest {
    pub config_id: Option<String>,
    pub key: String,
    pub permissions: Option<ApiKeyPermissions>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyApiKeyResponse {
    pub valid: bool,
    pub error: Option<VerifyApiKeyErrorBody>,
    pub key: Option<ApiKeyPublicRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyApiKeyErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "tryAgainIn")]
    pub try_again_in: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyValidationError {
    pub code: &'static str,
    pub status: StatusCode,
    pub try_again_in: Option<i64>,
}

pub fn verify_endpoint(
    configurations: SharedConfigurations,
) -> openauth_core::api::AsyncAuthEndpoint {
    endpoint(
        "/api-key/verify",
        Method::POST,
        configurations,
        |context, request, configurations| {
            Box::pin(async move {
                let input: VerifyApiKeyRequest = body(&request)?;
                let options = configurations.resolve(input.config_id.as_deref())?;
                if let Some(validator) = &options.custom_api_key_validator {
                    if !validator(context, &input.key).await? {
                        return json(
                            StatusCode::OK,
                            &VerifyApiKeyResponse {
                                valid: false,
                                error: Some(VerifyApiKeyErrorBody {
                                    code: errors::INVALID_API_KEY.to_owned(),
                                    message: errors::message(errors::INVALID_API_KEY).to_owned(),
                                    try_again_in: None,
                                }),
                                key: None,
                            },
                        );
                    }
                }
                let hashed = if options.disable_key_hashing {
                    input.key
                } else {
                    default_key_hasher(&input.key)
                };
                match validate_api_key(context, &options, &hashed, input.permissions.as_ref()).await
                {
                    Ok(api_key) => {
                        if options.defer_updates {
                            let _ = cleanup::delete_all_expired_api_keys(context, &options, false)
                                .await;
                        }
                        json(
                            StatusCode::OK,
                            &VerifyApiKeyResponse {
                                valid: true,
                                error: None,
                                key: Some(api_key.public()),
                            },
                        )
                    }
                    Err(error) => json(
                        StatusCode::OK,
                        &VerifyApiKeyResponse {
                            valid: false,
                            error: Some(VerifyApiKeyErrorBody {
                                code: error.code.to_owned(),
                                message: errors::message(error.code).to_owned(),
                                try_again_in: error.try_again_in,
                            }),
                            key: None,
                        },
                    ),
                }
            })
        },
    )
}

pub async fn validate_api_key(
    context: &AuthContext,
    options: &ApiKeyConfiguration,
    hashed_key: &str,
    required_permissions: Option<&ApiKeyPermissions>,
) -> Result<ApiKeyRecord, ApiKeyValidationError> {
    let store = ApiKeyStore::new(context, options);
    let mut api_key = store
        .get_by_hash(hashed_key)
        .await
        .map_err(|_| validation_error(errors::INVALID_API_KEY, StatusCode::UNAUTHORIZED))?
        .ok_or_else(|| validation_error(errors::INVALID_API_KEY, StatusCode::UNAUTHORIZED))?;
    if !api_key.enabled {
        return Err(validation_error(
            errors::KEY_DISABLED,
            StatusCode::UNAUTHORIZED,
        ));
    }
    let now = OffsetDateTime::now_utc();
    if api_key
        .expires_at
        .is_some_and(|expires_at| now > expires_at)
    {
        let _ = store.delete(&api_key).await;
        return Err(validation_error(
            errors::KEY_EXPIRED,
            StatusCode::UNAUTHORIZED,
        ));
    }
    if !permissions::allows(api_key.permissions.as_ref(), required_permissions) {
        return Err(validation_error(
            errors::KEY_NOT_FOUND,
            StatusCode::UNAUTHORIZED,
        ));
    }
    let mut remaining = api_key.remaining;
    let mut last_refill_at = api_key.last_refill_at;
    if api_key.remaining == Some(0) && api_key.refill_amount.is_none() {
        let _ = store.delete(&api_key).await;
        return Err(validation_error(
            errors::USAGE_EXCEEDED,
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    if let Some(current_remaining) = remaining {
        if let (Some(refill_interval), Some(refill_amount)) =
            (api_key.refill_interval, api_key.refill_amount)
        {
            let last = last_refill_at.unwrap_or(api_key.created_at);
            if (now - last).whole_milliseconds() > i128::from(refill_interval) {
                remaining = Some(refill_amount);
                last_refill_at = Some(now);
            }
        }
        if remaining == Some(0) {
            return Err(validation_error(
                errors::USAGE_EXCEEDED,
                StatusCode::TOO_MANY_REQUESTS,
            ));
        }
        if current_remaining > 0 || remaining.is_some_and(|value| value > 0) {
            remaining = remaining.map(|value| value.saturating_sub(1));
        }
    }
    let rate_limit = rate_limit::check(&api_key, options, now);
    if !rate_limit.success {
        return Err(ApiKeyValidationError {
            code: errors::RATE_LIMIT_EXCEEDED,
            status: StatusCode::UNAUTHORIZED,
            try_again_in: rate_limit.try_again_in,
        });
    }
    api_key.remaining = remaining;
    api_key.last_refill_at = last_refill_at;
    if let Some(last_request) = rate_limit.last_request {
        api_key.last_request = Some(last_request);
    }
    if let Some(request_count) = rate_limit.request_count {
        api_key.request_count = request_count;
    }
    api_key.updated_at = now;
    if options.defer_updates {
        let updated = api_key.clone();
        let options = options.clone();
        let context = context.clone();
        let task_context = context.clone();
        if !context.run_background_task(Box::pin(async move {
            let _ = ApiKeyStore::new(&task_context, &options)
                .update(&updated)
                .await;
        })) {
            store.update(&api_key).await.map_err(|_| {
                validation_error(
                    errors::FAILED_TO_UPDATE_API_KEY,
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;
        }
    } else {
        store.update(&api_key).await.map_err(|_| {
            validation_error(
                errors::FAILED_TO_UPDATE_API_KEY,
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;
    }
    Ok(api_key)
}

fn validation_error(code: &'static str, status: StatusCode) -> ApiKeyValidationError {
    ApiKeyValidationError {
        code,
        status,
        try_again_in: None,
    }
}
