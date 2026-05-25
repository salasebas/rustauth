use super::common::*;

#[tokio::test]
async fn token_endpoint_missing_grant_type_returns_unsupported_grant_type(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(default_provider()?, adapter())?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            "client_id=client_1",
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response)?;
    assert_eq!(body["error"], "unsupported_grant_type");
    Ok(())
}

#[tokio::test]
async fn oauth_token_endpoints_return_oauth_json_for_malformed_basic_auth(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(default_provider()?, adapter())?;
    let token_headers = [
        "Basic not-base64!!!".to_owned(),
        format!("Basic {}", STANDARD.encode("client-without-colon")),
        format!("Basic {}", STANDARD.encode([0xff])),
    ];

    for header_value in token_headers {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{BASE_URL}/api/auth/oauth2/token"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, header_value)
            .body(b"grant_type=client_credentials&scope=read".to_vec())?;

        let response = router.handle_async(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response)?["error"], "invalid_client");
    }

    for path in ["/api/auth/oauth2/introspect", "/api/auth/oauth2/revoke"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{BASE_URL}{path}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, "Basic not-base64!!!")
            .body(b"token=opaque".to_vec())?;

        let response = router.handle_async(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response)?["error"], "invalid_client");
    }
    Ok(())
}

#[tokio::test]
async fn client_credentials_token_returns_bearer_token_and_persists_opaque_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            scopes: vec!["read:reports".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],"scope":"read:reports"}"#,
        Some(&cookie),
    )
    .await?;
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=read%3Areports",
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response)?;
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["scope"], "read:reports");
    assert!(token["access_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(adapter.len("oauth_access_token").await, 1);
    Ok(())
}

#[tokio::test]
async fn client_credentials_rejects_oidc_scopes() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],"scope":"openid profile offline_access"}"#,
        Some(&cookie),
    )
    .await?;
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=openid%20profile",
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");
    Ok(())
}

#[tokio::test]
async fn token_endpoint_prefers_basic_auth_over_body_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            scopes: vec!["read:reports".to_owned()],
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],"scope":"read:reports"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("{BASE_URL}/api/auth/oauth2/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .body(
            b"grant_type=client_credentials&client_id=wrong&client_secret=wrong&scope=read%3Areports"
                .to_vec(),
        )?;

    let response = router.handle_async(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["scope"], "read:reports");
    Ok(())
}

#[tokio::test]
async fn token_endpoint_rejects_expired_client_secret() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            scopes: vec!["read:reports".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],"scope":"read:reports"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    adapter
        .update(
            Update::new("oauth_client")
                .where_clause(Where::new(
                    "client_id",
                    DbValue::String(client_id.to_owned()),
                ))
                .data(
                    "client_secret_expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::seconds(1)),
                ),
        )
        .await?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            &format!(
                "grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=read%3Areports"
            ),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
async fn refresh_token_grant_rotates_and_revokes_previous_refresh_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let first = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let refresh_token = first["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;
    let body = format!(
        "grant_type=refresh_token&client_id={client_id}&client_secret={client_secret}&refresh_token={refresh_token}"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response)?;
    assert_ne!(
        refreshed["refresh_token"].as_str(),
        Some(refresh_token),
        "refresh grant must rotate refresh tokens"
    );
    let refresh_records = adapter.records("oauth_refresh_token").await;
    assert_eq!(refresh_records.len(), 2);
    assert!(refresh_records
        .iter()
        .any(|record| matches!(record.get("revoked"), Some(DbValue::Timestamp(_)))));
    Ok(())
}

#[tokio::test]
async fn refresh_token_replay_revokes_refresh_token_family(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let first = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let old_refresh = first["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;
    let body = format!(
        "grant_type=refresh_token&client_id={client_id}&client_secret={client_secret}&refresh_token={old_refresh}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let new_refresh = json_body(response)?["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?
        .to_owned();

    let replay = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let body = format!(
        "grant_type=refresh_token&client_id={client_id}&client_secret={client_secret}&refresh_token={}",
        query_encode(&new_refresh)
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
async fn introspect_and_revoke_require_valid_client_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let tokens = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!("token={}", query_encode(access_token)),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_client");

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/revoke",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret=wrong",
                query_encode(access_token)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_client");

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["active"], true);

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/revoke",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn introspect_and_revoke_respect_token_type_hint() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let tokens = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret={}",
                query_encode(refresh_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["active"], false);

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&token_type_hint=refresh_token&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["active"], false);

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/revoke",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret={}",
                query_encode(refresh_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_token");

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/revoke",
            &format!(
                "token={}&token_type_hint=refresh_token&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_token");

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&client_id={client_id}&client_secret={}",
                query_encode(refresh_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["active"], true);
    Ok(())
}

#[tokio::test]
async fn resource_parameter_issues_jwt_access_token_with_oauth_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec!["https://api.example.com".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens = exchange_authorization_code_with_resource(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        Some("https://api.example.com"),
    )
    .await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let claims = decode_jwt_payload(access_token)?;

    assert_eq!(claims["iss"], BASE_URL);
    assert_eq!(claims["aud"], "https://api.example.com");
    assert_eq!(claims["azp"], client["client_id"]);
    assert_eq!(claims["sub"], "user_1");
    assert_eq!(claims["scope"], "openid offline_access");
    assert_eq!(adapter.len("oauth_access_token").await, 0);
    Ok(())
}

#[tokio::test]
async fn resource_array_issues_jwt_access_token_with_multiple_audiences(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec![
                "https://api.example.com".to_owned(),
                "https://mcp.example.com".to_owned(),
            ],
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    let code = authorization_code_from_location(&response)?;
    let body = json!({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": "https://rp.example/callback",
        "code_verifier": verifier,
        "resource": ["https://api.example.com", "https://mcp.example.com"]
    });
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/token",
            &body.to_string(),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response)?["access_token"]
        .as_str()
        .ok_or("missing access_token")?
        .to_owned();
    let claims = decode_jwt_payload(&token)?;
    assert_eq!(
        claims["aud"],
        json!(["https://api.example.com", "https://mcp.example.com"])
    );
    Ok(())
}

#[tokio::test]
async fn resource_form_repeated_issues_multi_audience_and_invalid_json_resource_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec![
                "https://api.example.com".to_owned(),
                "https://files.example.com".to_owned(),
            ],
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Ffiles.example.com&code_verifier={verifier}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let access_token = json_body(response)?["access_token"]
        .as_str()
        .ok_or("missing access_token")?
        .to_owned();
    let claims = decode_jwt_payload(&access_token)?;
    assert_eq!(
        claims["aud"],
        json!(["https://api.example.com", "https://files.example.com"])
    );

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/token",
            &format!(
                r#"{{"grant_type":"client_credentials","client_id":"{client_id}","client_secret":"{client_secret}","resource":["https://api.example.com",7]}}"#
            ),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn custom_id_token_claims_and_token_response_fields_are_added(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            custom_id_token_claims: Some(CustomIdTokenClaimsResolver::new(|_| async {
                Ok(serde_json::Map::from_iter([(
                    "https://example.com/organization".to_owned(),
                    json!("org_1"),
                )]))
            })),
            custom_token_response_fields: Some(CustomTokenResponseFieldsResolver::new(|_| async {
                Ok(serde_json::Map::from_iter([
                    ("issued_by".to_owned(), json!("openauth")),
                    ("access_token".to_owned(), json!("must-not-override")),
                ]))
            })),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
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

    assert_eq!(tokens["issued_by"], "openauth");
    assert_ne!(tokens["access_token"], "must-not-override");
    let id_token = tokens["id_token"].as_str().ok_or("missing id_token")?;
    assert_eq!(
        decode_jwt_payload(id_token)?["https://example.com/organization"],
        "org_1"
    );
    Ok(())
}

#[tokio::test]
async fn custom_token_response_failure_does_not_persist_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            custom_token_response_fields: Some(CustomTokenResponseFieldsResolver::new(|_| async {
                Err(OpenAuthError::Api(
                    "invalid_request: custom response failed".to_owned(),
                ))
            })),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier={verifier}"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    assert_eq!(adapter.len("oauth_access_token").await, 0);
    assert_eq!(adapter.len("oauth_refresh_token").await, 0);
    Ok(())
}

#[tokio::test]
async fn custom_access_and_userinfo_claims_are_added() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            custom_access_token_claims: Some(CustomAccessTokenClaimsResolver::new(
                |input| async move {
                    assert_eq!(input.reference_id.as_deref(), None);
                    Ok(serde_json::Map::from_iter([(
                        "https://example.com/role".to_owned(),
                        json!("admin"),
                    )]))
                },
            )),
            custom_userinfo_claims: Some(CustomUserInfoClaimsResolver::new(|input| async move {
                assert!(input.scopes.iter().any(|scope| scope == "openid"));
                Ok(serde_json::Map::from_iter([(
                    "https://example.com/userinfo".to_owned(),
                    json!("custom"),
                )]))
            })),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let tokens = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;

    let introspection = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(introspection.status(), StatusCode::OK);
    assert_eq!(
        json_body(introspection)?["https://example.com/role"],
        "admin"
    );

    let userinfo = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            access_token,
        )?)
        .await?;
    assert_eq!(userinfo.status(), StatusCode::OK);
    assert_eq!(
        json_body(userinfo)?["https://example.com/userinfo"],
        "custom"
    );
    Ok(())
}

#[tokio::test]
async fn userinfo_returns_claims_by_explicit_openid_profile_and_email_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid profile email","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;

    let openid = exchange_authorization_code_with_scope(
        &router,
        &cookie,
        client_id,
        client_secret,
        "openid",
    )
    .await?;
    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            openid["access_token"]
                .as_str()
                .ok_or("missing access_token")?,
        )?)
        .await?;
    let body = json_body(response)?;
    assert!(body["sub"].is_string());
    assert!(body.get("name").is_none());
    assert!(body.get("email").is_none());

    let profile = exchange_authorization_code_with_scope(
        &router,
        &cookie,
        client_id,
        client_secret,
        "openid profile",
    )
    .await?;
    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            profile["access_token"]
                .as_str()
                .ok_or("missing access_token")?,
        )?)
        .await?;
    let body = json_body(response)?;
    assert_eq!(body["name"], "Ada Lovelace");
    assert!(body.get("email").is_none());

    let email = exchange_authorization_code_with_scope(
        &router,
        &cookie,
        client_id,
        client_secret,
        "openid email",
    )
    .await?;
    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            email["access_token"]
                .as_str()
                .ok_or("missing access_token")?,
        )?)
        .await?;
    let body = json_body(response)?;
    assert_eq!(body["email"], "ada@example.com");
    assert_eq!(body["email_verified"], true);
    assert!(body.get("name").is_none());
    Ok(())
}

#[tokio::test]
async fn userinfo_rejects_tokens_without_openid_scope() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"profile","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens = exchange_authorization_code_with_scope(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "profile",
    )
    .await?;

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            tokens["access_token"]
                .as_str()
                .ok_or("missing access_token")?,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");
    Ok(())
}

#[tokio::test]
async fn scope_expirations_use_shortest_matching_scope() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            scopes: vec!["read:payments".to_owned(), "write:payments".to_owned()],
            scope_expirations: BTreeMap::from([
                ("read:payments".to_owned(), 1800),
                ("write:payments".to_owned(), 60),
            ]),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],"scope":"read:payments write:payments"}"#,
        Some(&cookie),
    )
    .await?;
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=read%3Apayments%20write%3Apayments",
        client["client_id"].as_str().ok_or("missing client_id")?,
        query_encode(client["client_secret"].as_str().ok_or("missing client_secret")?)
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert!(body["expires_in"]
        .as_i64()
        .is_some_and(|value| value <= 60 && value > 0));
    Ok(())
}

#[tokio::test]
async fn client_credentials_uses_default_scopes_when_client_has_no_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    let router = router(
        oauth_provider(OAuthProviderOptions {
            scopes: vec!["read:payments".to_owned(), "write:payments".to_owned()],
            client_credential_grant_default_scopes: vec!["read:payments".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let mut client = DbRecord::new();
    client.insert(
        "id".to_owned(),
        DbValue::String("oauth_client_default_scopes".to_owned()),
    );
    client.insert(
        "client_id".to_owned(),
        DbValue::String("client_default_scopes".to_owned()),
    );
    client.insert(
        "client_secret".to_owned(),
        DbValue::String(URL_SAFE_NO_PAD.encode(Sha256::digest(b"secret_default_scopes"))),
    );
    client.insert("scopes".to_owned(), DbValue::Null);
    client.insert(
        "grant_types".to_owned(),
        DbValue::StringArray(vec!["client_credentials".to_owned()]),
    );
    client.insert(
        "token_endpoint_auth_method".to_owned(),
        DbValue::String("client_secret_post".to_owned()),
    );
    client.insert("redirect_uris".to_owned(), DbValue::StringArray(Vec::new()));
    client.insert("public".to_owned(), DbValue::Boolean(false));
    adapter.create(create_query("oauth_client", client)).await?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            "grant_type=client_credentials&client_id=client_default_scopes&client_secret=secret_default_scopes",
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["scope"], "read:payments");
    Ok(())
}

#[tokio::test]
async fn prefixes_and_custom_generators_are_applied_without_storing_prefixes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            prefixes: OAuthTokenPrefixes {
                opaque_access_token: Some("oa_at_".to_owned()),
                refresh_token: Some("oa_rt_".to_owned()),
                client_secret: Some("oa_cs_".to_owned()),
            },
            generate_client_id: Some(StringGeneratorResolver::new(|| async {
                Ok("client_custom".to_owned())
            })),
            generate_client_secret: Some(StringGeneratorResolver::new(|| async {
                Ok("secret_custom".to_owned())
            })),
            generate_opaque_access_token: Some(StringGeneratorResolver::new(|| async {
                Ok("access_custom".to_owned())
            })),
            generate_refresh_token: Some(StringGeneratorResolver::new(|| async {
                Ok("refresh_custom".to_owned())
            })),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    assert_eq!(client["client_id"], "client_custom");
    assert_eq!(client["client_secret"], "oa_cs_secret_custom");

    let tokens =
        exchange_authorization_code(&router, &cookie, "client_custom", "oa_cs_secret_custom")
            .await?;
    assert_eq!(tokens["access_token"], "oa_at_access_custom");
    assert_eq!(tokens["refresh_token"], "oa_rt_refresh_custom");

    let stored_access = adapter
        .find_many(FindMany::new("oauth_access_token").where_clause(Where::new(
            "client_id",
            DbValue::String("client_custom".to_owned()),
        )))
        .await?;
    assert_ne!(
        stored_access.first().and_then(|record| record.get("token")),
        Some(&DbValue::String("oa_at_access_custom".to_owned()))
    );

    let refresh_body = format!(
        "grant_type=refresh_token&client_id=client_custom&client_secret={}&refresh_token={}",
        query_encode("oa_cs_secret_custom"),
        query_encode("oa_rt_refresh_custom")
    );
    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            &refresh_body,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn format_refresh_token_wraps_returned_token_and_decodes_refresh_grant(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            prefixes: OAuthTokenPrefixes {
                refresh_token: Some("oa_rt_".to_owned()),
                ..OAuthTokenPrefixes::default()
            },
            generate_refresh_token: Some(StringGeneratorResolver::new(|| async {
                Ok("raw_refresh".to_owned())
            })),
            format_refresh_token: Some(RefreshTokenFormatter::new(
                |input| async move {
                    Ok(format!(
                        "wrapped:{}:{}",
                        input.session_id.unwrap_or_default(),
                        input.token
                    ))
                },
                |token| async move {
                    let raw = token
                        .rsplit(':')
                        .next()
                        .ok_or_else(|| OpenAuthError::Api("invalid wrapped token".to_owned()))?;
                    Ok(RefreshTokenFormatDecodeOutput {
                        session_id: Some("session_1".to_owned()),
                        token: raw.to_owned(),
                    })
                },
            )),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let tokens = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    assert_eq!(
        tokens["refresh_token"],
        "oa_rt_wrapped:session_1:raw_refresh"
    );
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;
    let introspection = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&client_id={client_id}&client_secret={}",
                query_encode(refresh_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(introspection.status(), StatusCode::OK);
    assert_eq!(json_body(introspection)?["active"], true);

    let body = format!(
        "grant_type=refresh_token&client_id={client_id}&client_secret={}&refresh_token={}",
        query_encode(client_secret),
        query_encode(refresh_token)
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn custom_store_hash_callbacks_are_used_for_client_secrets_and_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            generate_client_secret: Some(StringGeneratorResolver::new(|| async {
                Ok("secret_hash".to_owned())
            })),
            generate_opaque_access_token: Some(StringGeneratorResolver::new(|| async {
                Ok("access_hash".to_owned())
            })),
            generate_refresh_token: Some(StringGeneratorResolver::new(|| async {
                Ok("refresh_hash".to_owned())
            })),
            hash_client_secret: Some(ClientSecretHashResolver::new(|input| async move {
                Ok(format!("client-hash:{}", input.secret))
            })),
            hash_token: Some(TokenHashResolver::new(|input| async move {
                Ok(format!("token-hash:{}:{}", input.token_type, input.token))
            })),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    assert_eq!(client["client_secret"], "secret_hash");

    let stored_client = adapter.records("oauth_client").await;
    assert_eq!(
        stored_client
            .first()
            .and_then(|record| record.get("client_secret")),
        Some(&DbValue::String("client-hash:secret_hash".to_owned()))
    );

    exchange_authorization_code(&router, &cookie, client_id, "secret_hash").await?;
    let access_tokens = adapter.records("oauth_access_token").await;
    assert_eq!(
        access_tokens.first().and_then(|record| record.get("token")),
        Some(&DbValue::String(
            "token-hash:access_token:access_hash".to_owned()
        ))
    );
    let refresh_tokens = adapter.records("oauth_refresh_token").await;
    assert_eq!(
        refresh_tokens
            .first()
            .and_then(|record| record.get("token")),
        Some(&DbValue::String(
            "token-hash:refresh_token:refresh_hash".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn resource_parameter_rejects_unconfigured_audience() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec!["https://api.example.com".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&resource=https%3A%2F%2Fevil.example&code_verifier={verifier}"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}
