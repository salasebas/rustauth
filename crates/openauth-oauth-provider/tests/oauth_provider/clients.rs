use super::common::*;

#[tokio::test]
async fn dynamic_registration_creates_confidential_client_and_hashes_secret(
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

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response)?;
    let client_id = body["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = body["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    assert_eq!(body["scope"], "openid email");

    let stored = adapter.records("oauth_client").await;
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].get("client_id"),
        Some(&DbValue::String(client_id.to_owned()))
    );
    assert_ne!(
        stored[0].get("client_secret"),
        Some(&DbValue::String(client_secret.to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_uses_default_scopes_and_configured_secret_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            client_registration_default_scopes: vec!["email".to_owned()],
            client_registration_client_secret_expiration: Some(600),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"]}"#,
        Some(&cookie),
    )
    .await?;

    assert_eq!(client["scope"], "email");
    let expires_at = client["client_secret_expires_at"]
        .as_i64()
        .ok_or("missing client_secret_expires_at")?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(expires_at > now && expires_at <= now + 600);
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_confidential_client_secret_does_not_expire_by_default(
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
        r#"{"redirect_uris":["https://rp.example/callback"]}"#,
        Some(&cookie),
    )
    .await?;

    assert_eq!(client["client_secret_expires_at"], 0);
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_rejects_invalid_client_metadata(
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
    let invalid_payloads = [
        r#"{"redirect_uris":["https://rp.example/callback"],"token_endpoint_auth_method":"private_key_jwt"}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["implicit"]}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"response_types":["token"]}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"skip_consent":true}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["not-a-url"]}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"require_pkce":false}"#,
    ];

    for payload in invalid_payloads {
        let response = router
            .handle_async(request(
                Method::POST,
                "/api/auth/oauth2/register",
                payload,
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "payload should fail: {payload}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_rejects_unsafe_redirect_urls(
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
    let invalid_payloads = [
        r#"{"redirect_uris":["javascript:alert(1)"]}"#,
        r#"{"redirect_uris":["data:text/html,<script>"]}"#,
        r#"{"redirect_uris":["vbscript:msgbox"]}"#,
        r#"{"redirect_uris":[""]}"#,
        r#"{"redirect_uris":["http://example.com/callback"]}"#,
        r#"{"redirect_uris":["http://192.168.1.1/callback"]}"#,
        r#"{"redirect_uris":["http://localhost.evil.com/callback"]}"#,
        r#"{"redirect_uris":["http://127.0.0.1.evil.com/callback"]}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["javascript:alert(1)"]}"#,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["http://example.com/logout"]}"#,
    ];

    for payload in invalid_payloads {
        let response = router
            .handle_async(request(
                Method::POST,
                "/api/auth/oauth2/register",
                payload,
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "payload should fail: {payload}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_allows_https_loopback_and_custom_scheme_redirects(
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
    let valid_payloads = [
        r#"{"redirect_uris":["https://rp.example/callback"]}"#,
        r#"{"redirect_uris":["http://localhost:3000/callback"]}"#,
        r#"{"redirect_uris":["http://127.0.0.1:8080/callback"]}"#,
        r#"{"redirect_uris":["http://[::1]:3000/callback"]}"#,
        r#"{"redirect_uris":["myapp://oauth/callback"]}"#,
    ];

    for payload in valid_payloads {
        let response = router
            .handle_async(request(
                Method::POST,
                "/api/auth/oauth2/register",
                payload,
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "payload should pass: {payload}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn client_reference_owns_clients_and_flows_into_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            client_reference: Some(ClientReferenceResolver::new(|input| async move {
                Ok(input.user.map(|user| {
                    if user.id == "user_1" {
                        "org_1".to_owned()
                    } else {
                        "org_other".to_owned()
                    }
                }))
            })),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let client = create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        &cookie,
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    assert_eq!(client["user_id"], Value::Null);
    assert_eq!(client["reference_id"], "org_1");

    let tokens = exchange_authorization_code(
        &router,
        &cookie,
        client_id,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
    )
    .await?;
    assert!(tokens["access_token"].is_string());

    let access_tokens = adapter
        .find_many(FindMany::new("oauth_access_token").where_clause(Where::new(
            "client_id",
            DbValue::String(client_id.to_owned()),
        )))
        .await?;
    assert_eq!(
        access_tokens
            .first()
            .and_then(|record| record.get("reference_id")),
        Some(&DbValue::String("org_1".to_owned()))
    );

    let refresh_tokens = adapter
        .find_many(
            FindMany::new("oauth_refresh_token").where_clause(Where::new(
                "client_id",
                DbValue::String(client_id.to_owned()),
            )),
        )
        .await?;
    assert_eq!(
        refresh_tokens
            .first()
            .and_then(|record| record.get("reference_id")),
        Some(&DbValue::String("org_1".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn client_privileges_can_deny_client_crud_actions() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            client_privileges: Some(ClientPrivilegesResolver::new(|input| async move {
                Ok(input.action != ClientPrivilegeAction::Update)
            })),
            ..default_options()
        })?,
        adapter,
    )?;
    let client = create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        &cookie,
    )
    .await?;
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/admin/oauth2/update-client",
            &format!(
                r#"{{"client_id":"{}","update":{{"client_name":"Denied"}}}}"#,
                client["client_id"].as_str().ok_or("missing client_id")?
            ),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn public_client_prelogin_requires_allow_flag_and_signed_oauth_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked = router(default_provider()?, adapter())?;
    let response = blocked
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/public-client-prelogin",
            r#"{"client_id":"client_1","oauth_query":"exp=4102444800&sig=invalid"}"#,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_public_client_prelogin: true,
            ..default_options()
        })?,
        adapter,
    )?;
    let client = create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"client_name":"Login Client"}"#,
        &cookie,
    )
    .await?;
    let signed_query = signed_oauth_query(4_102_444_800)?;
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/public-client-prelogin",
            &format!(
                r#"{{"client_id":"{}","oauth_query":"{}"}}"#,
                client["client_id"].as_str().ok_or("missing client_id")?,
                signed_query
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["client_name"], "Login Client");
    assert!(body.get("client_secret").is_none());
    Ok(())
}

#[tokio::test]
async fn cached_trusted_clients_reject_manual_update_delete_and_rotate(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            cached_trusted_clients: BTreeSet::from(["trusted_client".to_owned()]),
            generate_client_id: Some(StringGeneratorResolver::new(|| async {
                Ok("trusted_client".to_owned())
            })),
            ..default_options()
        })?,
        adapter,
    )?;
    create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        &cookie,
    )
    .await?;

    for (path, body) in [
        (
            "/api/auth/admin/oauth2/update-client",
            r#"{"client_id":"trusted_client","update":{"client_name":"Denied"}}"#,
        ),
        (
            "/api/auth/oauth2/client/rotate-secret",
            r#"{"client_id":"trusted_client"}"#,
        ),
        (
            "/api/auth/oauth2/delete-client",
            r#"{"client_id":"trusted_client"}"#,
        ),
    ] {
        let response = router
            .handle_async(request(Method::POST, path, body, Some(&cookie))?)
            .await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json_body(response)?["error"], "invalid_client");
    }
    Ok(())
}

#[tokio::test]
async fn cached_trusted_clients_reuse_cached_db_client_on_later_reads(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            cached_trusted_clients: BTreeSet::from(["trusted_client".to_owned()]),
            generate_client_id: Some(StringGeneratorResolver::new(|| async {
                Ok("trusted_client".to_owned())
            })),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"client_name":"Cached Name","scope":"openid"}"#,
        &cookie,
    )
    .await?;

    let first = router
        .handle_async(request(
            Method::GET,
            "/api/auth/oauth2/public-client?client_id=trusted_client",
            "",
            None,
        )?)
        .await?;
    assert_eq!(json_body(first)?["client_name"], "Cached Name");

    adapter
        .update(
            Update::new("oauth_client")
                .where_clause(Where::new(
                    "client_id",
                    DbValue::String("trusted_client".to_owned()),
                ))
                .data("name", DbValue::String("Mutated Name".to_owned())),
        )
        .await?;

    let second = router
        .handle_async(request(
            Method::GET,
            "/api/auth/oauth2/public-client?client_id=trusted_client",
            "",
            None,
        )?)
        .await?;
    assert_eq!(json_body(second)?["client_name"], "Cached Name");
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_cannot_enable_rp_initiated_logout(
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
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["https://rp.example/logout"],"enable_end_session":true}"#,
        Some(&cookie),
    )
    .await?;

    assert!(client.get("enable_end_session").is_none_or(Value::is_null));
    let stored = adapter.records("oauth_client").await;
    assert_eq!(stored[0].get("enable_end_session"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn client_management_endpoints_reject_cross_user_ownership(
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&owner_cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-client?client_id={client_id}"),
            "",
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["error"], "access_denied");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(r#"{{"client_id":"{client_id}","update":{{"client_name":"stolen"}}}}"#),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/client/rotate-secret",
            &format!(r#"{{"client_id":"{client_id}"}}"#),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/delete-client",
            &format!(r#"{{"client_id":"{client_id}"}}"#),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-client?client_id={client_id}"),
            "",
            Some(&owner_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn rotate_secret_rejects_public_clients() -> Result<(), Box<dyn std::error::Error>> {
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
        r#"{"redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none","type":"native","scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/client/rotate-secret",
            &format!(r#"{{"client_id":"{client_id}"}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
async fn update_client_preserves_omitted_fields() -> Result<(), Box<dyn std::error::Error>> {
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

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(r#"{{"client_id":"{client_id}","update":{{"client_name":"renamed"}}}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["client_name"], "renamed");
    assert_eq!(
        body["redirect_uris"],
        json!(["https://rp.example/callback"])
    );
    assert_eq!(body["scope"], "openid email");
    Ok(())
}

#[tokio::test]
async fn update_client_rejects_token_auth_method_changes() -> Result<(), Box<dyn std::error::Error>>
{
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
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(
                r#"{{"client_id":"{client_id}","update":{{"token_endpoint_auth_method":"none"}}}}"#
            ),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_client_metadata");
    Ok(())
}

#[tokio::test]
async fn update_client_rejects_invalid_scope() -> Result<(), Box<dyn std::error::Error>> {
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

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(r#"{{"client_id":"{client_id}","update":{{"scope":"admin"}}}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");
    Ok(())
}
