use super::common::*;

#[test]
fn generic_oauth_plugin_exposes_metadata_endpoints_and_errors() {
    let plugin = generic_oauth_with(GenericOAuthOptions {
        config: vec![example_config()],
    });

    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.version.as_deref(), Some(openauth_plugins::VERSION));
    assert_eq!(plugin.endpoints.len(), 3);
    assert!(plugin
        .error_codes
        .iter()
        .any(|code| code.code == "ISSUER_MISMATCH"));
}

#[test]
fn generic_oauth_init_registers_configured_social_providers() {
    let plugin = generic_oauth_with(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin.clone()],
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>,
    )
    .unwrap();

    assert!(context.social_provider("example").is_some());
}

#[test]
fn generic_oauth_duplicate_provider_ids_keep_first_provider() {
    let mut duplicate = example_config();
    duplicate.authorization_url = Some("https://other.example.com/oauth/authorize".to_owned());
    let plugin = generic_oauth_with(GenericOAuthOptions {
        config: vec![example_config(), duplicate],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin.clone()],
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>,
    )
    .unwrap();

    assert!(context.social_provider("example").is_some());
}

#[tokio::test]
async fn generic_oauth_registered_provider_refreshes_with_discovery_token_endpoint() {
    let body = Arc::new(Mutex::new(String::new()));
    let token_url = capture_post_server(
        Arc::clone(&body),
        r#"{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer"}"#,
    );
    let discovery_hits = Arc::new(AtomicUsize::new(0));
    let discovery_url = discovery_server_with_token(
        Arc::clone(&discovery_hits),
        &token_url,
        "https://idp.example.com/oauth/userinfo",
    );
    let plugin = generic_oauth_with(GenericOAuthOptions {
        config: vec![loopback_http_config(GenericOAuthConfig::discovery(
            "discovery",
            "client-1",
            Some("secret-1"),
            discovery_url,
        ))],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>,
    )
    .unwrap();
    let tokens = context
        .social_provider("discovery")
        .unwrap()
        .refresh_access_token("refresh-token".to_owned())
        .await
        .unwrap();

    assert_eq!(tokens.access_token.as_deref(), Some("new-access"));
    assert_eq!(discovery_hits.load(Ordering::SeqCst), 1);
    assert!(body.lock().unwrap().contains("refresh_token=refresh-token"));
}
