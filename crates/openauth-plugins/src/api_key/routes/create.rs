use http::{Method, StatusCode};
use openauth_core::crypto::random::generate_random_string;
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    body, current_identity, endpoint, error, future_expiration, json, metadata_is_object,
    request_is_external, valid_prefix, SharedConfigurations,
};
use crate::api_key::cleanup;
use crate::api_key::errors;
use crate::api_key::hashing::{default_key_generator, default_key_hasher};
use crate::api_key::models::{ApiKeyCreateRecord, ApiKeyRecord};
use crate::api_key::options::{ApiKeyGeneratorInput, ApiKeyPermissions, ApiKeyReference};
use crate::api_key::organization::{ensure_organization_permission, ApiKeyAction};
use crate::api_key::storage::ApiKeyStore;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
    pub config_id: Option<String>,
    pub name: Option<String>,
    pub expires_in: Option<i64>,
    pub prefix: Option<String>,
    pub remaining: Option<i64>,
    pub metadata: Option<Value>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub permissions: Option<ApiKeyPermissions>,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
}

pub fn create_endpoint(
    configurations: SharedConfigurations,
) -> openauth_core::api::AsyncAuthEndpoint {
    endpoint(
        "/api-key/create",
        Method::POST,
        configurations,
        |context, request, configurations| {
            Box::pin(async move {
                let input: CreateApiKeyRequest = body(&request)?;
                let options = configurations.resolve(input.config_id.as_deref())?;
                let identity = current_identity(context, &request).await?;
                let is_external = request_is_external();
                let reference_id = match options.reference {
                    ApiKeyReference::Organization => {
                        let Some(organization_id) = input.organization_id.as_deref() else {
                            return error(
                                StatusCode::BAD_REQUEST,
                                errors::ORGANIZATION_ID_REQUIRED,
                            );
                        };
                        let user_id =
                            match identity.as_ref().map(|identity| identity.user.id.as_str()) {
                                Some(user_id) => user_id,
                                // Only trusted server-side callers may name the actor explicitly.
                                None if !is_external => match input.user_id.as_deref() {
                                    Some(user_id) => user_id,
                                    None => {
                                        return error(
                                            StatusCode::UNAUTHORIZED,
                                            errors::UNAUTHORIZED_SESSION,
                                        )
                                    }
                                },
                                None => {
                                    return error(
                                        StatusCode::UNAUTHORIZED,
                                        errors::UNAUTHORIZED_SESSION,
                                    )
                                }
                            };
                        if let Err(error) = ensure_organization_permission(
                            context,
                            user_id,
                            organization_id,
                            ApiKeyAction::Create,
                        )
                        .await
                        {
                            return error_response_from_openauth(error);
                        }
                        organization_id.to_owned()
                    }
                    ApiKeyReference::User => {
                        if let Some(identity) = &identity {
                            if input
                                .user_id
                                .as_deref()
                                .is_some_and(|user_id| user_id != identity.user.id)
                            {
                                return error(
                                    StatusCode::UNAUTHORIZED,
                                    errors::UNAUTHORIZED_SESSION,
                                );
                            }
                            identity.user.id.clone()
                        } else if !is_external {
                            // Trusted server-side caller may target an explicit user id.
                            match input.user_id.clone() {
                                Some(user_id) => user_id,
                                None => {
                                    return error(
                                        StatusCode::UNAUTHORIZED,
                                        errors::UNAUTHORIZED_SESSION,
                                    )
                                }
                            }
                        } else {
                            return error(StatusCode::UNAUTHORIZED, errors::UNAUTHORIZED_SESSION);
                        }
                    }
                };

                let uses_server_only_props = input.remaining.is_some()
                    || input.refill_amount.is_some()
                    || input.refill_interval.is_some()
                    || input.rate_limit_time_window.is_some()
                    || input.rate_limit_max.is_some()
                    || input.rate_limit_enabled.is_some()
                    || input.permissions.is_some();
                if is_external && uses_server_only_props {
                    return error(StatusCode::BAD_REQUEST, errors::SERVER_ONLY_PROPERTY);
                }

                if let Err(code) = validate_input(&input, &options) {
                    return error(StatusCode::BAD_REQUEST, code);
                }
                let _ = cleanup::delete_all_expired_api_keys(context, &options, false).await;

                let prefix = input
                    .prefix
                    .as_deref()
                    .or(options.default_prefix.as_deref());
                let key = match &options.custom_key_generator {
                    Some(generator) => {
                        generator(ApiKeyGeneratorInput {
                            length: options.default_key_length,
                            prefix: prefix.map(str::to_owned),
                        })
                        .await?
                    }
                    None => default_key_generator(options.default_key_length, prefix),
                };
                let hashed = if options.disable_key_hashing {
                    key.clone()
                } else {
                    default_key_hasher(&key)
                };
                let now = OffsetDateTime::now_utc();
                let start = options.starting_characters.should_store.then(|| {
                    key.chars()
                        .take(options.starting_characters.characters_length)
                        .collect::<String>()
                });
                let expires_at = input
                    .expires_in
                    .and_then(|seconds| (seconds > 0).then_some(seconds))
                    .or(options.key_expiration.default_expires_in)
                    .and_then(|seconds| {
                        (seconds > 0)
                            .then(|| future_expiration(Some(seconds)))
                            .flatten()
                    });
                let config_id = options
                    .config_id
                    .clone()
                    .unwrap_or_else(|| "default".to_owned());
                let record = ApiKeyRecord {
                    id: generate_random_string(32),
                    config_id,
                    name: input.name.clone(),
                    start,
                    prefix: prefix.map(str::to_owned),
                    key: hashed,
                    reference_id,
                    refill_interval: input.refill_interval,
                    refill_amount: input.refill_amount,
                    last_refill_at: None,
                    enabled: true,
                    rate_limit_enabled: input
                        .rate_limit_enabled
                        .unwrap_or(options.rate_limit.enabled),
                    rate_limit_time_window: Some(
                        input
                            .rate_limit_time_window
                            .unwrap_or(options.rate_limit.time_window),
                    ),
                    rate_limit_max: Some(
                        input
                            .rate_limit_max
                            .unwrap_or(options.rate_limit.max_requests),
                    ),
                    request_count: 0,
                    remaining: input.remaining,
                    last_request: None,
                    expires_at,
                    created_at: now,
                    updated_at: now,
                    metadata: input.metadata.clone(),
                    permissions: input
                        .permissions
                        .clone()
                        .or_else(|| options.default_permissions.clone()),
                };
                let created = ApiKeyStore::new(context, &options).create(record).await?;
                json(
                    StatusCode::OK,
                    &ApiKeyCreateRecord {
                        record: created.public(),
                        key,
                    },
                )
            })
        },
    )
}

fn validate_input(
    input: &CreateApiKeyRequest,
    options: &crate::api_key::options::ApiKeyConfiguration,
) -> Result<(), &'static str> {
    if let Some(metadata) = &input.metadata {
        if !options.enable_metadata {
            return Err(errors::METADATA_DISABLED);
        }
        if !metadata_is_object(&Some(metadata.clone())) {
            return Err(errors::INVALID_METADATA_TYPE);
        }
    }
    if input.refill_amount.is_some() && input.refill_interval.is_none() {
        return Err(errors::REFILL_AMOUNT_AND_INTERVAL_REQUIRED);
    }
    if input.refill_interval.is_some() && input.refill_amount.is_none() {
        return Err(errors::REFILL_INTERVAL_AND_AMOUNT_REQUIRED);
    }
    if let Some(expires_in) = input.expires_in {
        if options.key_expiration.disable_custom_expires_time {
            return Err(errors::KEY_DISABLED_EXPIRATION);
        }
        let days = expires_in / (60 * 60 * 24);
        if days < options.key_expiration.min_expires_in_days {
            return Err(errors::EXPIRES_IN_IS_TOO_SMALL);
        }
        if days > options.key_expiration.max_expires_in_days {
            return Err(errors::EXPIRES_IN_IS_TOO_LARGE);
        }
    }
    if let Some(prefix) = &input.prefix {
        if !valid_prefix(prefix)
            || prefix.len() < options.minimum_prefix_length
            || prefix.len() > options.maximum_prefix_length
        {
            return Err(errors::INVALID_PREFIX_LENGTH);
        }
    }
    if let Some(name) = &input.name {
        if name.len() < options.minimum_name_length || name.len() > options.maximum_name_length {
            return Err(errors::INVALID_NAME_LENGTH);
        }
    } else if options.require_name {
        return Err(errors::NAME_REQUIRED);
    }
    Ok(())
}

fn error_response_from_openauth(
    error: OpenAuthError,
) -> Result<openauth_core::api::ApiResponse, OpenAuthError> {
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
