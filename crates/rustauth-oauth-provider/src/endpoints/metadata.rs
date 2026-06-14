use super::*;

pub(super) fn metadata_endpoint(
    path: &'static str,
    options: Arc<ResolvedOAuthProviderOptions>,
    mode: MetadataEndpointMode,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, _request| {
            let options = Arc::clone(&options);
            async move {
                match mode {
                    MetadataEndpointMode::OpenIdConfiguration => {
                        if !options.scopes.contains(&"openid".to_owned()) {
                            return error_response(OAuthProviderError::new(
                                StatusCode::NOT_FOUND,
                                "not_found",
                                "OpenID Connect is disabled",
                            ));
                        }
                        well_known_metadata_response(&oidc_server_metadata(&context, &options))
                    }
                    MetadataEndpointMode::OAuthAuthorizationServer => {
                        let mut metadata = if options.scopes.contains(&"openid".to_owned()) {
                            serde_json::to_value(oidc_server_metadata(&context, &options))
                        } else {
                            serde_json::to_value(auth_server_metadata(&context, &options))
                        }
                        .map_err(|error| RustAuthError::Api(error.to_string()))?;
                        crate::mcp::merge_authorization_server_metadata(
                            &mut metadata,
                            options.mcp.as_ref(),
                        );
                        well_known_metadata_response(&metadata)
                    }
                }
            }
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataEndpointMode {
    OAuthAuthorizationServer,
    OpenIdConfiguration,
}
