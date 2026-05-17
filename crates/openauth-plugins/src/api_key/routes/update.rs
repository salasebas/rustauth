use http::{Method, StatusCode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    body, config_id_matches, current_identity, endpoint, error, future_expiration, json,
    metadata_is_object, SharedConfigurations,
};
use crate::api_key::errors;
use crate::api_key::models::ApiKeyRecord;
use crate::api_key::options::{ApiKeyPermissions, ApiKeyReference};
use crate::api_key::organization::{ensure_organization_permission, owns_user_key, ApiKeyAction};
use crate::api_key::storage::ApiKeyStore;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApiKeyRequest {
    pub key_id: String,
    pub config_id: Option<String>,
    pub user_id: Option<String>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<i64>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "UpdateField::is_missing")]
    pub expires_in: UpdateField<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    #[serde(default, skip_serializing_if = "UpdateField::is_missing")]
    pub permissions: UpdateField<ApiKeyPermissions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UpdateField<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<T> UpdateField<T> {
    fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
}

impl<'de, T> Deserialize<'de> for UpdateField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer)
            .map(|value| value.map(Self::Value).unwrap_or(Self::Null))
    }
}

impl<T> Serialize for UpdateField<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Missing | Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

pub fn update_endpoint(
    configurations: SharedConfigurations,
) -> openauth_core::api::AsyncAuthEndpoint {
    endpoint(
        "/api-key/update",
        Method::POST,
        configurations,
        |context, request, configurations| {
            Box::pin(async move {
                let input: UpdateApiKeyRequest = body(&request)?;
                let options = configurations.resolve(input.config_id.as_deref())?;
                let identity = current_identity(context, &request).await?;
                let actor_user_id = match &identity {
                    Some(identity) => {
                        if input
                            .user_id
                            .as_deref()
                            .is_some_and(|user_id| user_id != identity.user.id)
                        {
                            return error(StatusCode::UNAUTHORIZED, errors::UNAUTHORIZED_SESSION);
                        }
                        identity.user.id.clone()
                    }
                    None => {
                        let Some(user_id) = input.user_id.clone() else {
                            return error(StatusCode::UNAUTHORIZED, errors::UNAUTHORIZED_SESSION);
                        };
                        user_id
                    }
                };
                let store = ApiKeyStore::new(context, &options);
                let Some(mut api_key) = store.get_by_id(&input.key_id).await? else {
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
                            &actor_user_id,
                        ) => {}
                    ApiKeyReference::User => {
                        return error(StatusCode::NOT_FOUND, errors::KEY_NOT_FOUND)
                    }
                    ApiKeyReference::Organization => {
                        if let Err(error) = ensure_organization_permission(
                            context,
                            &actor_user_id,
                            &api_key.reference_id,
                            ApiKeyAction::Update,
                        )
                        .await
                        {
                            return error_response_from_openauth(error);
                        }
                    }
                }
                let has_cookie = request.headers().contains_key(http::header::COOKIE);
                if has_cookie && has_server_only_update(&input) {
                    return error(StatusCode::BAD_REQUEST, errors::SERVER_ONLY_PROPERTY);
                }
                if no_values_to_update(&input, &options) {
                    return error(StatusCode::BAD_REQUEST, errors::NO_VALUES_TO_UPDATE);
                }
                if let Err(code) = apply_update(&mut api_key, input, &options) {
                    return error(StatusCode::BAD_REQUEST, code);
                }
                let Some(updated) = store.update(&api_key).await? else {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        errors::FAILED_TO_UPDATE_API_KEY,
                    );
                };
                json(StatusCode::OK, &updated.public())
            })
        },
    )
}

fn no_values_to_update(
    input: &UpdateApiKeyRequest,
    options: &crate::api_key::options::ApiKeyConfiguration,
) -> bool {
    input.name.is_none()
        && input.enabled.is_none()
        && input.remaining.is_none()
        && input.refill_amount.is_none()
        && input.refill_interval.is_none()
        && (input.metadata.is_none() || !options.enable_metadata)
        && input.expires_in.is_missing()
        && input.rate_limit_enabled.is_none()
        && input.rate_limit_time_window.is_none()
        && input.rate_limit_max.is_none()
        && input.permissions.is_missing()
}

fn has_server_only_update(input: &UpdateApiKeyRequest) -> bool {
    input.remaining.is_some()
        || input.refill_amount.is_some()
        || input.refill_interval.is_some()
        || input.rate_limit_enabled.is_some()
        || input.rate_limit_time_window.is_some()
        || input.rate_limit_max.is_some()
        || !input.permissions.is_missing()
}

fn apply_update(
    api_key: &mut ApiKeyRecord,
    input: UpdateApiKeyRequest,
    options: &crate::api_key::options::ApiKeyConfiguration,
) -> Result<(), &'static str> {
    if let Some(name) = input.name {
        if name.len() < options.minimum_name_length || name.len() > options.maximum_name_length {
            return Err(errors::INVALID_NAME_LENGTH);
        }
        api_key.name = Some(name);
    }
    if let Some(metadata) = input.metadata.filter(|_| options.enable_metadata) {
        if !metadata_is_object(&Some(metadata.clone())) {
            return Err(errors::INVALID_METADATA_TYPE);
        }
        api_key.metadata = Some(metadata);
    }
    if input.refill_amount.is_some() ^ input.refill_interval.is_some() {
        return Err(errors::REFILL_AMOUNT_AND_INTERVAL_REQUIRED);
    }
    match input.expires_in {
        UpdateField::Missing => {}
        UpdateField::Null => {
            if options.key_expiration.disable_custom_expires_time {
                return Err(errors::KEY_DISABLED_EXPIRATION);
            }
            api_key.expires_at = None;
        }
        UpdateField::Value(expires_in) => {
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
            api_key.expires_at = future_expiration(Some(expires_in));
        }
    }
    if let Some(enabled) = input.enabled {
        api_key.enabled = enabled;
    }
    if input.remaining.is_some() {
        api_key.remaining = input.remaining;
    }
    if input.refill_amount.is_some() {
        api_key.refill_amount = input.refill_amount;
        api_key.refill_interval = input.refill_interval;
    }
    if let Some(enabled) = input.rate_limit_enabled {
        api_key.rate_limit_enabled = enabled;
    }
    if input.rate_limit_time_window.is_some() {
        api_key.rate_limit_time_window = input.rate_limit_time_window;
    }
    if input.rate_limit_max.is_some() {
        api_key.rate_limit_max = input.rate_limit_max;
    }
    match input.permissions {
        UpdateField::Missing => {}
        UpdateField::Null => api_key.permissions = None,
        UpdateField::Value(permissions) => api_key.permissions = Some(permissions),
    }
    api_key.updated_at = OffsetDateTime::now_utc();
    Ok(())
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
