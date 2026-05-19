use std::sync::Arc;

use http::{header, Method};
use openauth_core::api::{
    create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions, OpenApiOperation,
};
use serde_json::json;

use crate::options::{SamlConfig, SsoOptions};
use crate::saml::metadata::service_provider_metadata;
use crate::store::SsoProviderStore;
use crate::utils;

use super::support::query_param;

pub(super) fn endpoint(options: Arc<SsoOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sso/saml2/sp/metadata",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("getSSOServiceProviderMetadata")
            .openapi(OpenApiOperation::new("getSSOServiceProviderMetadata").tag("SSO")),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                if query_param(&request, "format").as_deref() == Some("json") {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({
                            "code": "UNSUPPORTED_METADATA_FORMAT",
                            "message": "SAML metadata is only available as XML"
                        }),
                    );
                }
                let Some(provider_id) = query_param(&request, "providerId") else {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "MISSING_PROVIDER_ID"}),
                    );
                };
                let Some(adapter) = context.adapter.as_deref() else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                let Some(provider) = SsoProviderStore::new(adapter)
                    .find_by_provider_id(&provider_id)
                    .await?
                else {
                    return utils::json(
                        http::StatusCode::NOT_FOUND,
                        &json!({"code": "PROVIDER_NOT_FOUND"}),
                    );
                };
                let Some(config) = provider
                    .saml_config
                    .as_deref()
                    .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
                else {
                    return utils::json(
                        http::StatusCode::BAD_REQUEST,
                        &json!({"code": "INVALID_SAML_CONFIG"}),
                    );
                };
                let metadata = service_provider_metadata(
                    &provider.provider_id,
                    &context.base_url,
                    &config,
                    options.saml.enable_single_logout,
                );
                http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/xml")
                    .body(metadata.into_bytes())
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))
            })
        },
    )
}
