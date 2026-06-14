use super::*;

pub(super) fn protected_resource_metadata_endpoint(
    options: Arc<ResolvedOAuthProviderOptions>,
) -> Option<AsyncAuthEndpoint> {
    let mcp = options.mcp.clone()?;
    Some(create_auth_endpoint(
        "/.well-known/oauth-protected-resource",
        Method::GET,
        AuthEndpointOptions::new().operation_id("getMcpProtectedResourceMetadata"),
        move |context, _request| {
            let options = Arc::clone(&options);
            let mcp = mcp.clone();
            async move {
                let metadata =
                    crate::mcp::protected_resource_metadata_document(&context, &options, &mcp)?;
                no_store_json_response(StatusCode::OK, &metadata)
            }
        },
    ))
}
