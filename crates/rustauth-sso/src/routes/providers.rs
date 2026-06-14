use std::sync::Arc;

use http::Method;
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use serde_json::json;

use crate::audit;
use crate::openapi::{
    error_code_response, provider_id_body_schema, provider_id_query_parameter,
    sso_provider_list_response, sso_provider_response, success_response,
};
use crate::options::{SsoAuditEvent, SsoAuditEventKind, SsoAuditSeverity, SsoOptions};
use crate::org::{accessible_providers, can_manage_provider};
use crate::store::SsoProviderStore;
use crate::utils;

use super::support::{
    authenticated_user, invalid_provider_id, query_param, unauthorized, valid_provider_id,
    ProviderIdBody,
};

pub(super) fn list_endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/providers",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("listSSOProviders")
            .openapi(
                OpenApiOperation::new("listSSOProviders")
                    .tag("SSO")
                    .response("200", sso_provider_list_response()),
            ),
        {
            let options = Arc::clone(&options);
            move |context, request| {
                let options = Arc::clone(&options);
                async move {
                    let Some((adapter, user_id)) = authenticated_user(&context, &request).await?
                    else {
                        return unauthorized();
                    };
                    let providers = accessible_providers(
                        &context,
                        adapter.as_ref(),
                        &user_id,
                        SsoProviderStore::new_with_options(adapter.as_ref(), &options)
                            .list()
                            .await?,
                    )
                    .await?
                    .into_iter()
                    .map(|provider| {
                        provider.sanitized_with_options(&context.base_url, Some(&options))
                    })
                    .collect::<Vec<_>>();
                    utils::json(http::StatusCode::OK, &json!({ "providers": providers }))
                }
            }
        },
    )
}

pub(super) fn get_endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/get-provider",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("getSSOProvider")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .openapi(
                OpenApiOperation::new("getSSOProvider")
                    .tag("SSO")
                    .parameter(provider_id_query_parameter())
                    .response("200", sso_provider_response("SSO provider"))
                    .response("400", error_code_response("Invalid provider id"))
                    .response("404", error_code_response("Provider not found")),
            ),
        {
            let options = Arc::clone(&options);
            move |context, request| {
                let options = Arc::clone(&options);
                async move {
                    let Some((adapter, user_id)) = authenticated_user(&context, &request).await?
                    else {
                        return unauthorized();
                    };
                    let provider_id = match query_param(&request, "providerId")
                        .filter(|value| !value.is_empty())
                    {
                        Some(provider_id) => provider_id,
                        None => parse_request_body::<ProviderIdBody>(&request)?.provider_id,
                    };
                    if !valid_provider_id(&provider_id) {
                        return invalid_provider_id();
                    }
                    let Some(provider) =
                        SsoProviderStore::new_with_options(adapter.as_ref(), &options)
                            .find_by_provider_id(&provider_id)
                            .await?
                    else {
                        return utils::json(
                            http::StatusCode::NOT_FOUND,
                            &json!({"code": "PROVIDER_NOT_FOUND"}),
                        );
                    };
                    if !can_manage_provider(&context, adapter.as_ref(), &user_id, &provider).await?
                    {
                        return utils::json(
                            http::StatusCode::FORBIDDEN,
                            &json!({"code": "FORBIDDEN"}),
                        );
                    }
                    utils::json(
                        http::StatusCode::OK,
                        &provider.sanitized_with_options(&context.base_url, Some(&options)),
                    )
                }
            }
        },
    )
}

pub(super) fn delete_endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/delete-provider",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("deleteSSOProvider")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(provider_id_body_schema())
            .openapi(
                OpenApiOperation::new("deleteSSOProvider")
                    .tag("SSO")
                    .response("200", success_response("Provider deleted")),
            ),
        {
            let options = Arc::clone(&options);
            move |context, request| {
                let options = Arc::clone(&options);
                async move {
                    let Some((adapter, user_id)) = authenticated_user(&context, &request).await?
                    else {
                        return unauthorized();
                    };
                    let body = parse_request_body::<ProviderIdBody>(&request)?;
                    if !valid_provider_id(&body.provider_id) {
                        return invalid_provider_id();
                    }
                    let store = SsoProviderStore::new_with_options(adapter.as_ref(), &options);
                    let Some(provider) = store.find_by_provider_id(&body.provider_id).await? else {
                        return utils::json(
                            http::StatusCode::NOT_FOUND,
                            &json!({"code": "PROVIDER_NOT_FOUND"}),
                        );
                    };
                    if !can_manage_provider(&context, adapter.as_ref(), &user_id, &provider).await?
                    {
                        return utils::json(
                            http::StatusCode::FORBIDDEN,
                            &json!({"code": "FORBIDDEN"}),
                        );
                    }
                    store.delete(&body.provider_id).await?;
                    let mut event = SsoAuditEvent::new(
                        SsoAuditEventKind::ProviderDeleted,
                        SsoAuditSeverity::Warn,
                    )
                    .provider_id(provider.provider_id.clone())
                    .user_id(user_id);
                    if let Some(organization_id) = provider.organization_id {
                        event = event.organization_id(organization_id);
                    }
                    audit::emit(&context, &options, event).await;
                    utils::json(http::StatusCode::OK, &json!({"success": true}))
                }
            }
        },
    )
}
