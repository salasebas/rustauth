use super::common::*;

#[tokio::test]
async fn authorization_code_flow_issues_access_and_refresh_tokens(
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
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&state=abc&code_challenge={challenge}&code_challenge_method=S256"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location")?;
    let redirect = url::Url::parse(location)?;
    let code = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then_some(value.into_owned()))
        .ok_or("missing code")?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier={verifier}"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response)?;
    assert!(token["access_token"].as_str().is_some());
    assert!(token["refresh_token"].as_str().is_some());
    assert_eq!(adapter.len("oauth_access_token").await, 1);
    assert_eq!(adapter.len("oauth_refresh_token").await, 1);
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_defaults_missing_scope_to_client_scopes(
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
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier={verifier}"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = json_body(response)?;
    assert_eq!(tokens["scope"], "openid offline_access");
    assert!(tokens["refresh_token"].as_str().is_some());
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_enforces_pkce_s256_for_public_clients(
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
        r#"{"redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none","type":"native","scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let authorize_without_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_without_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_with_challenge_only = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid&code_challenge={challenge}"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_challenge_only,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let authorize_with_method_only = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_method_only,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let authorize_with_plain_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid&code_challenge={challenge}&code_challenge_method=plain"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_plain_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let authorize_with_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let wrong_verifier_body = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier=wrong"
    );
    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            &wrong_verifier_body,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier={verifier}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_enforces_upstream_pkce_policy_for_confidential_clients(
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
    let default_client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let default_client_id = default_client["client_id"]
        .as_str()
        .ok_or("missing client_id")?;
    let without_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={default_client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid"
    );
    let response = router
        .handle_async(request(Method::GET, &without_pkce, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");

    let opt_out_client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","require_pkce":false,"skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let opt_out_client_id = opt_out_client["client_id"]
        .as_str()
        .ok_or("missing client_id")?;
    let openid_without_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={opt_out_client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &openid_without_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(authorization_code_from_location(&response).is_ok());

    let offline_without_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={opt_out_client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &offline_without_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_rejects_spurious_pkce_verifier(
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","require_pkce":false,"skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier=unexpected"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_requires_active_session_and_user_before_tokens(
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
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    let expired_session_code = authorization_code_from_location(&response)?;
    adapter
        .update(
            Update::new("session")
                .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
                .data(
                    "expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::seconds(1)),
                ),
        )
        .await?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={expired_session_code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier={verifier}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(adapter.len("oauth_access_token").await, 0);
    assert_eq!(adapter.len("oauth_refresh_token").await, 0);

    adapter
        .update(
            Update::new("session")
                .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
                .data(
                    "expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() + Duration::hours(1)),
                ),
        )
        .await?;
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    let missing_user_code = authorization_code_from_location(&response)?;
    adapter
        .delete(
            Delete::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned()))),
        )
        .await?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={missing_user_code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier={verifier}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(adapter.len("oauth_access_token").await, 0);
    assert_eq!(adapter.len("oauth_refresh_token").await, 0);
    Ok(())
}

#[tokio::test]
async fn authorize_loopback_matching_uses_ip_literals_only(
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
    let localhost_client = register_client(
        &router,
        r#"{"redirect_uris":["http://localhost:3000/callback"],"scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let localhost_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={}&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback&scope=openid",
        localhost_client["client_id"].as_str().ok_or("missing client_id")?
    );
    let response = router
        .handle_async(request(Method::GET, &localhost_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let ip_client = register_client(
        &router,
        r#"{"redirect_uris":["http://127.0.0.2:3000/callback"],"scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let ip_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={}&redirect_uri=http%3A%2F%2F127.0.0.2%3A4000%2Fcallback&scope=openid&code_challenge={challenge}&code_challenge_method=S256",
        ip_client["client_id"].as_str().ok_or("missing client_id")?
    );
    let response = router
        .handle_async(request(Method::GET, &ip_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(authorization_code_from_location(&response).is_ok());
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_none_returns_login_required_without_session(
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
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=login-state&prompt=none&code_challenge={challenge}&code_challenge_method=S256"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.scheme(), "https");
    assert_eq!(redirect.host_str(), Some("rp.example"));
    assert_eq!(redirect.path(), "/callback");
    assert_eq!(
        redirect_query_value(&redirect, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("login-state")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_none_returns_consent_required_without_grant(
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
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20email&state=consent-state&prompt=none&code_challenge={challenge}&code_challenge_method=S256"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.scheme(), "https");
    assert_eq!(redirect.host_str(), Some("rp.example"));
    assert_eq!(redirect.path(), "/callback");
    assert_eq!(
        redirect_query_value(&redirect, "error").as_deref(),
        Some("consent_required")
    );
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("consent-state")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_none_rejects_supported_prompt_combinations(
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
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","require_pkce":false,"skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=prompt-state&prompt=none%20login%20unknown"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.host_str(), Some("rp.example"));
    assert_eq!(
        redirect_query_value(&redirect, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(
        redirect_query_value(&redirect, "error_description").as_deref(),
        Some("prompt none must only be used alone")
    );
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("prompt-state")
    );

    let bad_redirect_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&scope=openid&prompt=none%20login"
    );
    let response = router
        .handle_async(request(Method::GET, &bad_redirect_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::LOCATION).is_none());
    Ok(())
}

#[tokio::test]
async fn authorize_ignores_unknown_prompt_values() -> Result<(), Box<dyn std::error::Error>> {
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
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&prompt=unknown&code_challenge={challenge}&code_challenge_method=S256"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(authorization_code_from_location(&response).is_ok());
    Ok(())
}

#[tokio::test]
async fn authorize_request_uri_resolver_handles_origin_form_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            generate_client_id: Some(StringGeneratorResolver::new(|| async {
                Ok("resolved-client".to_owned())
            })),
            request_uri_resolver: Some(RequestUriResolver::new(|_| async {
                Ok(Some(vec![
                    ("response_type".to_owned(), "code".to_owned()),
                    ("client_id".to_owned(), "resolved-client".to_owned()),
                    (
                        "redirect_uri".to_owned(),
                        "https://rp.example/callback".to_owned(),
                    ),
                    ("scope".to_owned(), "openid".to_owned()),
                    ("state".to_owned(), "request-uri-state".to_owned()),
                    (
                        "code_challenge".to_owned(),
                        pkce_challenge("correct-horse-battery-staple"),
                    ),
                    ("code_challenge_method".to_owned(), "S256".to_owned()),
                ]))
            })),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","skip_consent":true}"#,
        &cookie,
    )
    .await?;
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("/api/auth/oauth2/authorize?request_uri=urn%3Atest%3Arequest")
                .header(header::COOKIE, cookie)
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("request-uri-state")
    );
    assert!(redirect_query_value(&redirect, "code").is_some());
    Ok(())
}

#[tokio::test]
async fn openid_authorization_code_issues_signed_id_token_and_jwks(
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid profile email","skip_consent":true}"#,
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
        "openid profile email",
    )
    .await?;
    let id_token = tokens["id_token"].as_str().ok_or("missing id_token")?;
    let claims = decode_jwt_payload(id_token)?;

    assert_eq!(claims["iss"], BASE_URL);
    assert_eq!(claims["aud"], client["client_id"]);
    assert_eq!(claims["sub"], "user_1");
    assert_eq!(claims["email"], "ada@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["name"], "Ada Lovelace");

    let jwks_response = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks = json_body(jwks_response)?;
    assert!(jwks["keys"].as_array().is_some_and(|keys| !keys.is_empty()));
    Ok(())
}

#[tokio::test]
async fn authorize_resolves_request_uri_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            request_uri_resolver: Some(RequestUriResolver::new(|input| async move {
                assert_eq!(input.request_uri, "urn:request:123");
                Ok(Some(vec![
                    ("response_type".to_owned(), "code".to_owned()),
                    (
                        "redirect_uri".to_owned(),
                        "https://rp.example/callback".to_owned(),
                    ),
                    ("scope".to_owned(), "openid offline_access".to_owned()),
                    (
                        "code_challenge".to_owned(),
                        pkce_challenge("correct-horse-battery-staple"),
                    ),
                    ("code_challenge_method".to_owned(), "S256".to_owned()),
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
    let path = format!(
        "/api/auth/oauth2/authorize?client_id={}&request_uri=urn%3Arequest%3A123",
        client["client_id"].as_str().ok_or("missing client_id")?
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(authorization_code_from_location(&response).is_ok());
    Ok(())
}

#[tokio::test]
async fn authorize_rejects_unallowed_scope_and_request_uri_client_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            request_uri_resolver: Some(RequestUriResolver::new(|_| async move {
                Ok(Some(vec![
                    ("response_type".to_owned(), "code".to_owned()),
                    ("client_id".to_owned(), "other_client".to_owned()),
                    (
                        "redirect_uri".to_owned(),
                        "https://rp.example/callback".to_owned(),
                    ),
                    ("scope".to_owned(), "openid".to_owned()),
                ]))
            })),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let invalid_scope_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=admin"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &invalid_scope_path,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");

    let mismatch_path =
        format!("/api/auth/oauth2/authorize?client_id={client_id}&request_uri=urn%3Amismatch");
    let response = router
        .handle_async(request(Method::GET, &mismatch_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn authorize_max_age_zero_forces_login_redirect() -> Result<(), Box<dyn std::error::Error>> {
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&max_age=0&code_challenge={challenge}&code_challenge_method=S256",
        client["client_id"].as_str().ok_or("missing client_id")?
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&header::HeaderValue::from_static("/login"))
    );
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_create_redirects_to_signup_page() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            signup_page: Some("/signup".to_owned()),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&prompt=create&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.path(), "/signup");
    assert_eq!(
        redirect_query_value(&redirect, "client_id").as_deref(),
        Some(client_id)
    );
    assert_eq!(
        redirect_query_value(&redirect, "redirect_uri").as_deref(),
        Some("https://rp.example/callback")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_create_continue_issues_code_when_session_exists(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            signup_page: Some("/signup".to_owned()),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","require_pkce":false,"skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=create-state&prompt=create"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/continue?request_id={request_id}&created=true"),
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert!(redirect_query_value(&redirect, "code").is_some());
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("create-state")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_select_account_redirects_to_select_account_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            select_account_page: Some("/select-account".to_owned()),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&prompt=select_account&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.path(), "/select-account");
    assert!(redirect_query_value(&redirect, "request_id").is_some());
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_select_account_continue_issues_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            select_account_page: Some("/select-account".to_owned()),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","require_pkce":false,"skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=select-state&prompt=select_account"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/continue?request_id={request_id}&selected=true"),
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert!(redirect_query_value(&redirect, "code").is_some());
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("select-state")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_post_login_continue_issues_code() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            post_login_page: Some("/post-login".to_owned()),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=post-login-state&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.path(), "/post-login");
    let request_id = redirect_query_value(&redirect, "request_id").ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/continue?request_id={request_id}&post_login=true"),
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert!(redirect_query_value(&redirect, "code").is_some());
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("post-login-state")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_post_login_redirect_callback_can_choose_custom_page(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            post_login_redirect: Some(PromptRedirectResolver::new(|input| async move {
                assert!(input.scopes.iter().any(|scope| scope == "openid"));
                Ok(Some("/mfa".to_owned()))
            })),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.path(), "/mfa");
    assert!(redirect_query_value(&redirect, "request_id").is_some());
    Ok(())
}
