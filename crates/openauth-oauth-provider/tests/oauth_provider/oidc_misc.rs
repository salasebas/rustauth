use super::common::*;

#[tokio::test]
async fn pairwise_subject_is_stable_by_sector_and_used_for_userinfo_and_introspection(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            pairwise_secret: Some("test-pairwise-secret-key-32chars!!".to_owned()),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client_a = register_client(
        &router,
        r#"{"redirect_uris":["https://rp-a.example/callback"],"scope":"openid email offline_access","subject_type":"pairwise","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_b = register_client(
        &router,
        r#"{"redirect_uris":["https://rp-b.example/callback"],"scope":"openid email offline_access","subject_type":"pairwise","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens_a = exchange_authorization_code_with_redirect(
        &router,
        &cookie,
        client_a["client_id"].as_str().ok_or("missing client_id")?,
        client_a["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "https://rp-a.example/callback",
    )
    .await?;
    let tokens_a_again = exchange_authorization_code_with_redirect(
        &router,
        &cookie,
        client_a["client_id"].as_str().ok_or("missing client_id")?,
        client_a["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "https://rp-a.example/callback",
    )
    .await?;
    let tokens_b = exchange_authorization_code_with_redirect(
        &router,
        &cookie,
        client_b["client_id"].as_str().ok_or("missing client_id")?,
        client_b["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "https://rp-b.example/callback",
    )
    .await?;
    let sub_a = decode_jwt_payload(tokens_a["id_token"].as_str().ok_or("missing id_token")?)?
        ["sub"]
        .as_str()
        .ok_or("missing sub")?
        .to_owned();
    let sub_a_again = decode_jwt_payload(
        tokens_a_again["id_token"]
            .as_str()
            .ok_or("missing id_token")?,
    )?["sub"]
        .as_str()
        .ok_or("missing sub")?
        .to_owned();
    let sub_b = decode_jwt_payload(tokens_b["id_token"].as_str().ok_or("missing id_token")?)?
        ["sub"]
        .as_str()
        .ok_or("missing sub")?
        .to_owned();

    assert_eq!(sub_a, sub_a_again);
    assert_ne!(sub_a, sub_b);

    let access_token = tokens_a["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let userinfo = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            access_token,
        )?)
        .await?;
    assert_eq!(userinfo.status(), StatusCode::OK);
    assert_eq!(json_body(userinfo)?["sub"], sub_a);

    let introspection = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&client_id={}&client_secret={}",
                query_encode(access_token),
                client_a["client_id"].as_str().ok_or("missing client_id")?,
                query_encode(
                    client_a["client_secret"]
                        .as_str()
                        .ok_or("missing client_secret")?
                )
            ),
        )?)
        .await?;
    assert_eq!(introspection.status(), StatusCode::OK);
    assert_eq!(json_body(introspection)?["sub"], sub_a);

    let refresh_token = tokens_a["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;
    let refresh_body = format!(
        "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={refresh_token}",
        client_a["client_id"].as_str().ok_or("missing client_id")?,
        client_a["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?
    );
    let refreshed = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            &refresh_body,
        )?)
        .await?;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let refreshed = json_body(refreshed)?;
    assert_eq!(
        decode_jwt_payload(refreshed["id_token"].as_str().ok_or("missing id_token")?)?["sub"],
        sub_a
    );
    Ok(())
}

#[tokio::test]
async fn pairwise_registration_requires_single_redirect_sector(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            pairwise_secret: Some("test-pairwise-secret-key-32chars!!".to_owned()),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback","https://other.example/callback"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_client_metadata");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example:443/callback","https://rp.example:8443/callback"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_client_metadata");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback","https://rp.example/alt"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
async fn mcp_helpers_return_metadata_challenge_and_validate_bearer_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let options = OAuthProviderOptions {
        disable_jwt_plugin: true,
        allow_dynamic_client_registration: true,
        ..default_options()
    };
    let plugin = oauth_provider(options.clone())?;
    let resolved = resolve_oauth_provider_options(options)?;
    let router = router(plugin, Arc::clone(&adapter))?;
    let context = create_auth_context_with_adapter(
        options_with_provider(oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?),
        adapter.clone(),
    )?;
    let auth_metadata = mcp_authorization_server_metadata(&context, &resolved);
    assert_eq!(auth_metadata["issuer"], BASE_URL);
    assert_eq!(
        auth_metadata["authorization_endpoint"],
        format!("{BASE_URL}/oauth2/authorize")
    );
    assert_eq!(
        auth_metadata["token_endpoint"],
        format!("{BASE_URL}/oauth2/token")
    );
    assert_eq!(
        auth_metadata["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );

    let resource_metadata =
        mcp_protected_resource_metadata(&context, &resolved, "https://mcp.example/sse")?;
    assert_eq!(resource_metadata["resource"], "https://mcp.example/sse");
    assert_eq!(
        resource_metadata["authorization_servers"],
        json!([BASE_URL])
    );
    assert_eq!(
        resource_metadata["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );

    let challenge = www_authenticate_for_resources(["https://mcp.example/sse"])?;
    assert!(challenge.contains(".well-known/oauth-protected-resource/sse"));
    let non_url = www_authenticate_for_resources(["urn:example:resource"]);
    assert!(matches!(
        non_url,
        Err(err) if err.contains("missing resource_metadata mapping")
    ));

    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens = exchange_authorization_code(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
    )
    .await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let active = validate_bearer_token(
        &context,
        adapter.as_ref(),
        &resolved,
        Some(&format!("Bearer {access_token}")),
    )
    .await?
    .ok_or("missing validated token")?;

    assert_eq!(active.subject.as_deref(), Some("user_1"));
    assert_eq!(active.client_id.as_deref(), client["client_id"].as_str());
    assert_eq!(active.scopes, ["openid", "offline_access"]);

    let invalid = validate_bearer_token(
        &context,
        adapter.as_ref(),
        &resolved,
        Some("Bearer invalid"),
    )
    .await?;
    assert!(invalid.is_none());
    Ok(())
}

#[tokio::test]
async fn rp_initiated_logout_rejects_invalid_id_token_hint(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(default_provider()?, adapter())?;
    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/oauth2/end-session?id_token_hint=not-a-jwt",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_token");
    Ok(())
}

#[tokio::test]
async fn rp_initiated_logout_deletes_session_and_redirects_to_registered_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["https://rp.example/logout"],"enable_end_session":true,"scope":"openid offline_access","skip_consent":true}"#,
        &cookie,
    )
    .await?;
    let tokens = exchange_authorization_code(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
    )
    .await?;
    let id_token = tokens["id_token"].as_str().ok_or("missing id_token")?;
    assert_eq!(decode_jwt_payload(id_token)?["sid"], "session_1");

    let logout_path = format!(
        "/api/auth/oauth2/end-session?id_token_hint={}&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Flogout&state=done",
        query_encode(id_token)
    );
    let response = router
        .handle_async(request(Method::GET, &logout_path, "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location")?;
    assert_eq!(location, "https://rp.example/logout?state=done");
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn rp_initiated_logout_rejects_clients_without_end_session_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["https://rp.example/logout"],"scope":"openid offline_access","skip_consent":true}"#,
        &cookie,
    )
    .await?;
    let tokens = exchange_authorization_code(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
    )
    .await?;
    let id_token = tokens["id_token"].as_str().ok_or("missing id_token")?;
    assert!(decode_jwt_payload(id_token)?.get("sid").is_none());

    let logout_path = format!(
        "/api/auth/oauth2/end-session?id_token_hint={}",
        query_encode(id_token)
    );
    let response = router
        .handle_async(request(Method::GET, &logout_path, "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_client");
    Ok(())
}
