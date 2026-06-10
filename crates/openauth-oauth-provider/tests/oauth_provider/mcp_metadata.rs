use super::common::*;

#[test]
fn oauth_provider_resolves_mcp_options() -> Result<(), Box<dyn std::error::Error>> {
    let options = OAuthProviderOptions {
        mcp: Some(McpOptions::default()),
        ..default_options()
    };
    let resolved = resolve_oauth_provider_options(options)?;

    assert_eq!(resolved.mcp.as_ref().ok_or("missing mcp")?.resource, None);
    Ok(())
}

#[test]
fn oauth_provider_rejects_invalid_mcp_resource() {
    let result = oauth_provider(OAuthProviderOptions {
        mcp: Some(McpOptions {
            resource: Some("not-a-url".to_owned()),
            ..McpOptions::default()
        }),
        ..default_options()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::InvalidMcpResource)
    );
}

#[tokio::test]
async fn mcp_enabled_registers_protected_resource_metadata_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            mcp: Some(McpOptions::default()),
            ..default_options()
        })?,
        adapter(),
    )?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-protected-resource",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["resource"], BASE_URL);
    assert_eq!(body["authorization_servers"], json!([BASE_URL]));
    assert_eq!(body["bearer_methods_supported"], json!(["header"]));
    Ok(())
}

#[tokio::test]
async fn mcp_enabled_supports_custom_resource() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            mcp: Some(McpOptions {
                resource: Some("https://api.example.com/mcp".to_owned()),
                ..McpOptions::default()
            }),
            ..default_options()
        })?,
        adapter(),
    )?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-protected-resource",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["resource"], "https://api.example.com/mcp");
    assert_eq!(body["authorization_servers"], json!([BASE_URL]));
    Ok(())
}

#[tokio::test]
async fn mcp_disabled_does_not_register_protected_resource_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            mcp: None,
            ..default_options()
        })?,
        adapter(),
    )?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-protected-resource",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn mcp_metadata_overrides_merge_into_discovery_documents(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut authorization_server = BTreeMap::new();
    authorization_server.insert(
        "service_documentation".to_owned(),
        json!("https://docs.example"),
    );
    let mut protected_resource = BTreeMap::new();
    protected_resource.insert("resource_name".to_owned(), json!("Example MCP"));

    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            mcp: Some(McpOptions {
                metadata: McpMetadataOverrides {
                    authorization_server: authorization_server.into_iter().collect(),
                    protected_resource: protected_resource.into_iter().collect(),
                },
                ..McpOptions::default()
            }),
            ..default_options()
        })?,
        adapter(),
    )?;

    let authorization_server = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-authorization-server",
            "",
            None,
        )?)
        .await?;
    assert_eq!(
        json_body(authorization_server)?["service_documentation"],
        "https://docs.example"
    );

    let protected_resource = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-protected-resource",
            "",
            None,
        )?)
        .await?;
    assert_eq!(
        json_body(protected_resource)?["resource_name"],
        "Example MCP"
    );
    Ok(())
}
