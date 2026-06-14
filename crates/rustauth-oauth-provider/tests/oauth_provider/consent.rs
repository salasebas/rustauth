use super::common::*;

#[tokio::test]
async fn consent_helpers_persist_update_delete_and_match_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: "client_1".to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        },
    )
    .await?;

    assert!(has_granted_scopes(&consent, &["openid".to_owned()]));
    assert!(has_granted_scopes(
        &consent,
        &["openid".to_owned(), "email".to_owned()]
    ));
    assert!(!has_granted_scopes(&consent, &["profile".to_owned()]));

    let updated = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: "client_1".to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: Some("ref_1".to_owned()),
            scopes: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
        },
    )
    .await?;

    assert_eq!(adapter.len("oauth_consent").await, 2);
    assert_eq!(updated.reference_id.as_deref(), Some("ref_1"));
    assert!(has_granted_scopes(&updated, &["profile".to_owned()]));

    let found = find_consent(adapter.as_ref(), "user_1", "client_1")
        .await?
        .ok_or("missing consent")?;
    assert_eq!(found.id, consent.id);

    delete_consent(adapter.as_ref(), "user_1", "client_1").await?;
    assert!(find_consent(adapter.as_ref(), "user_1", "client_1")
        .await?
        .is_none());
    assert_eq!(adapter.len("oauth_consent").await, 1);
    Ok(())
}

#[tokio::test]
async fn consent_endpoint_accepts_rejects_and_continue_without_flag_is_rejected(
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email offline_access"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let challenge = pkce_challenge("correct-horse-battery-staple");

    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20email&state=approve-state&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let consent_redirect = redirect_url(&response)?;
    assert_eq!(consent_redirect.path(), "/consent");
    let request_id =
        redirect_query_value(&consent_redirect, "request_id").ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/consent",
            &format!(r#"{{"request_id":"{}","accept":true}}"#, request_id),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let callback = redirect_url(&response)?;
    assert_eq!(callback.path(), "/callback");
    assert!(redirect_query_value(&callback, "code").is_some());
    assert_eq!(
        redirect_query_value(&callback, "state").as_deref(),
        Some("approve-state")
    );
    assert_eq!(adapter.len("oauth_consent").await, 1);

    let reject_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=email&state=reject-state&prompt=consent&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &reject_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let reject_request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/consent",
            &format!(r#"{{"request_id":"{}","accept":false}}"#, reject_request_id),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let rejected = redirect_url(&response)?;
    assert_eq!(
        redirect_query_value(&rejected, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        redirect_query_value(&rejected, "state").as_deref(),
        Some("reject-state")
    );

    let continue_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=email&state=continue-state&prompt=consent&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &continue_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let continue_request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;
    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/continue?request_id={continue_request_id}"),
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn consent_endpoint_accepts_subset_and_rejects_unrequested_scope(
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid profile email offline_access"}"#,
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
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20profile%20email&state=narrow-state&prompt=consent&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/consent",
            &format!(r#"{{"request_id":"{request_id}","accept":true,"scope":"openid admin"}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response)?;
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Scope not originally requested");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/consent",
            &format!(r#"{{"request_id":"{request_id}","accept":true,"scope":"openid profile"}}"#),
            Some(&cookie),
        )?)
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
    let token = json_body(response)?;
    assert_eq!(token["scope"], "openid profile");

    let stored = find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .ok_or("missing consent")?;
    assert_eq!(
        stored.scopes,
        vec!["openid".to_owned(), "profile".to_owned()]
    );
    Ok(())
}

#[tokio::test]
async fn continue_requires_matching_prompt_flag_and_rechecks_consent(
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
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=select-consent-state&prompt=select_account&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/continue",
            r#"{"created":true}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/continue",
            &format!(r#"{{"request_id":"{request_id}","created":true}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/continue",
            &format!(r#"{{"request_id":"{request_id}","selected":true}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.path(), "/consent");
    assert!(redirect_query_value(&redirect, "request_id").is_some());
    Ok(())
}

#[tokio::test]
async fn consent_management_endpoints_enforce_owner_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    seed_user_session_with(
        adapter.as_ref(),
        UserSeed {
            user_id: "user_2",
            session_id: "session_2",
            token: "token_2",
            name: "Grace Hopper",
            email: "grace@example.com",
        },
    )
    .await?;
    let owner_cookie = signed_session_cookie("token_1")?;
    let other_cookie = signed_session_cookie("token_2")?;
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
        Some(&owner_cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: client_id.to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned()],
        },
    )
    .await?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-consent?id={}", consent.id),
            "",
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-consent?id={}", consent.id),
            "",
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(
                r#"{{"id":"{}","update":{{"scopes":["openid","email"]}}}}"#,
                consent.id
            ),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/delete-consent",
            &format!(r#"{{"id":"{}"}}"#, consent.id),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(
                r#"{{"id":"{}","update":{{"scopes":["openid","email"]}}}}"#,
                consent.id
            ),
            Some(&owner_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/delete-consent",
            &format!(r#"{{"id":"{}"}}"#, consent.id),
            Some(&owner_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn update_consent_rejects_scopes_not_allowed_for_client(
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
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: client_id.to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned()],
        },
    )
    .await?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(
                r#"{{"id":"{}","update":{{"scopes":["email"]}}}}"#,
                consent.id
            ),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");

    let stored = find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .ok_or("missing consent")?;
    assert_eq!(stored.scopes, vec!["openid".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn update_consent_without_scopes_preserves_existing_scopes(
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
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: client_id.to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        },
    )
    .await?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(r#"{{"id":"{}","update":{{}}}}"#, consent.id),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let stored = find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .ok_or("missing consent")?;
    assert_eq!(stored.scopes, vec!["openid".to_owned(), "email".to_owned()]);
    Ok(())
}
