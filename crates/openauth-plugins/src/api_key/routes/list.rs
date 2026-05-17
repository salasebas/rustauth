use std::cmp::Ordering;
use std::collections::BTreeSet;

use http::{Method, StatusCode};
use openauth_core::db::SortDirection;
use serde::{Deserialize, Serialize};

use super::{
    current_identity, endpoint, error, json, query_param, query_usize, SharedConfigurations,
};
use crate::api_key::errors;
use crate::api_key::models::{ApiKeyPublicRecord, ApiKeyRecord};
use crate::api_key::options::ApiKeyReference;
use crate::api_key::organization::{ensure_organization_permission, ApiKeyAction};
use crate::api_key::storage::{ApiKeyStore, ListOptions};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListApiKeysQuery {
    pub config_id: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListApiKeysResponse {
    api_keys: Vec<ApiKeyPublicRecord>,
    total: u64,
    limit: Option<usize>,
    offset: Option<usize>,
}

pub fn list_endpoint(
    configurations: SharedConfigurations,
) -> openauth_core::api::AsyncAuthEndpoint {
    endpoint(
        "/api-key/list",
        Method::GET,
        configurations,
        |context, request, configurations| {
            Box::pin(async move {
                let config_id = query_param(&request, "configId");
                let organization_id = query_param(&request, "organizationId");
                let Some(identity) = current_identity(context, &request).await? else {
                    return error(StatusCode::UNAUTHORIZED, errors::UNAUTHORIZED_SESSION);
                };
                let expected_reference = if organization_id.is_some() {
                    ApiKeyReference::Organization
                } else {
                    ApiKeyReference::User
                };
                let reference_id = if let Some(organization_id) = organization_id {
                    if let Err(error) = ensure_organization_permission(
                        context,
                        &identity.user.id,
                        &organization_id,
                        ApiKeyAction::Read,
                    )
                    .await
                    {
                        return error_response_from_openauth(error);
                    }
                    organization_id
                } else {
                    identity.user.id
                };
                let limit = query_usize(&request, "limit");
                let offset = query_usize(&request, "offset");
                let sort_direction = match query_param(&request, "sortDirection").as_deref() {
                    Some("desc") => SortDirection::Desc,
                    _ => SortDirection::Asc,
                };
                let sort_by = query_param(&request, "sortBy");
                let mut api_keys = if let Some(config_id) = config_id.as_deref() {
                    let options = configurations.resolve(Some(config_id))?;
                    if options.reference != expected_reference {
                        Vec::new()
                    } else {
                        ApiKeyStore::new(context, &options)
                            .list(
                                &reference_id,
                                ListOptions {
                                    config_id: Some(
                                        options
                                            .config_id
                                            .clone()
                                            .unwrap_or_else(|| "default".to_owned()),
                                    ),
                                    limit: None,
                                    offset: None,
                                    sort_by: sort_by.clone(),
                                    sort_direction,
                                },
                            )
                            .await?
                            .api_keys
                    }
                } else {
                    list_all_configurations(
                        context,
                        &configurations,
                        &reference_id,
                        expected_reference,
                        sort_by.clone(),
                        sort_direction,
                    )
                    .await?
                };
                sort_api_keys(&mut api_keys, sort_by.as_deref(), sort_direction);
                let total = api_keys.len() as u64;
                let api_keys = paginate(api_keys, offset, limit)
                    .into_iter()
                    .map(|api_key| api_key.public())
                    .collect::<Vec<_>>();
                json(
                    StatusCode::OK,
                    &ListApiKeysResponse {
                        api_keys,
                        total,
                        limit,
                        offset,
                    },
                )
            })
        },
    )
}

async fn list_all_configurations(
    context: &openauth_core::context::AuthContext,
    configurations: &SharedConfigurations,
    reference_id: &str,
    expected_reference: ApiKeyReference,
    sort_by: Option<String>,
    sort_direction: SortDirection,
) -> Result<Vec<ApiKeyRecord>, openauth_core::error::OpenAuthError> {
    let mut seen = BTreeSet::new();
    let mut all = Vec::new();
    for configuration in configurations.all() {
        let options = configurations.resolve(configuration.config_id.as_deref())?;
        if options.reference != expected_reference {
            continue;
        }
        let config_id = options
            .config_id
            .clone()
            .unwrap_or_else(|| "default".to_owned());
        let result = ApiKeyStore::new(context, &options)
            .list(
                reference_id,
                ListOptions {
                    config_id: Some(config_id),
                    limit: None,
                    offset: None,
                    sort_by: sort_by.clone(),
                    sort_direction,
                },
            )
            .await?;
        for api_key in result.api_keys {
            if seen.insert(api_key.id.clone()) {
                all.push(api_key);
            }
        }
    }
    Ok(all)
}

fn sort_api_keys(
    api_keys: &mut [ApiKeyRecord],
    sort_by: Option<&str>,
    sort_direction: SortDirection,
) {
    let Some(sort_by) = sort_by else {
        return;
    };
    api_keys.sort_by(|left, right| compare_api_keys(left, right, sort_by));
    if sort_direction == SortDirection::Desc {
        api_keys.reverse();
    }
}

fn paginate(
    api_keys: Vec<ApiKeyRecord>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Vec<ApiKeyRecord> {
    let iter = api_keys.into_iter().skip(offset.unwrap_or(0));
    match limit {
        Some(limit) => iter.take(limit).collect(),
        None => iter.collect(),
    }
}

fn compare_api_keys(left: &ApiKeyRecord, right: &ApiKeyRecord, field: &str) -> Ordering {
    match field {
        "createdAt" | "created_at" => left.created_at.cmp(&right.created_at),
        "updatedAt" | "updated_at" => left.updated_at.cmp(&right.updated_at),
        "name" => left.name.cmp(&right.name),
        "expiresAt" | "expires_at" => left.expires_at.cmp(&right.expires_at),
        _ => left.id.cmp(&right.id),
    }
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
