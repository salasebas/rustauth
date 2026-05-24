use super::common::*;

#[tokio::test]
async fn sign_in_oauth2_route_returns_redirect_url() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(
                    br#"{"providerId":"example","callbackURL":"/dashboard","disableRedirect":true}"#
                        .to_vec(),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["redirect"], false);
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/oauth2/callback/example".to_owned())
    );
}

#[tokio::test]
async fn sign_in_oauth2_route_applies_dynamic_authorization_url_params() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config
        .authorization_url_params
        .insert("audience".to_owned(), "static".to_owned());
    config.authorization_url_params_callback =
        Some(Arc::new(|context: GenericOAuthParamsContext| {
            Box::pin(async move {
                assert_eq!(context.provider_id, "example");
                assert_eq!(context.flow, GenericOAuthFlow::SignIn);
                assert_eq!(
                    context.redirect_uri,
                    "https://app.example.com/oauth2/callback/example"
                );
                Ok(BTreeMap::from([
                    ("audience".to_owned(), "dynamic".to_owned()),
                    ("resource".to_owned(), "calendar".to_owned()),
                ]))
            })
        }));
    let context = context_with_plugin(
        adapter,
        generic_oauth(GenericOAuthOptions {
            config: vec![config],
        }),
    );
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    let url = sign_in_url(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();

    assert_eq!(query_value(&url, "audience"), Some("dynamic".to_owned()));
    assert_eq!(query_value(&url, "resource"), Some("calendar".to_owned()));
}

#[tokio::test]
async fn sign_in_oauth2_route_rejects_unknown_provider() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"missing"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "PROVIDER_CONFIG_NOT_FOUND");
}

#[tokio::test]
async fn sign_in_oauth2_route_rejects_invalid_client_id() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.client_id.clear();
    let context = context_with_plugin(
        adapter,
        generic_oauth(GenericOAuthOptions {
            config: vec![config],
        }),
    );
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"example"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_OAUTH_CONFIG");
}

#[tokio::test]
async fn sign_in_oauth2_route_rejects_missing_token_url() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.token_url = None;
    let context = context_with_plugin(
        adapter,
        generic_oauth(GenericOAuthOptions {
            config: vec![config],
        }),
    );
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"example"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "TOKEN_URL_NOT_FOUND");
}

#[tokio::test]
async fn sign_in_oauth2_route_rejects_required_issuer_without_issuer_config() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.issuer = None;
    config.require_issuer_validation = true;
    let context = context_with_plugin(
        adapter,
        generic_oauth(GenericOAuthOptions {
            config: vec![config],
        }),
    );
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"example"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ISSUER_MISSING");
}

#[tokio::test]
async fn oauth2_callback_redirects_oauth_error_query_with_description() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(adapter, oauth_plugin(example_config()));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("https://app.example.com/api/auth/oauth2/callback/example?error=access_denied&error_description=User%20denied")
                .body(Vec::new())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=access_denied&error_description=User+denied")
    );
}

#[tokio::test]
async fn oauth2_callback_creates_user_account_session_and_cookie() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(
        adapter.clone(),
        oauth_plugin(oauth_flow_config("oauth-user-1")),
    );
    let router = AuthRouter::try_new(context.clone(), Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), Some("/dashboard"));
    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_email("ada@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.name, "Ada Lovelace");
    assert!(DbUserStore::new(adapter.as_ref())
        .find_account_by_provider_account("oauth-user-1", "example")
        .await
        .unwrap()
        .is_some());
    let token = session_token_from_response(&context, &response);
    assert!(DbSessionStore::new(adapter.as_ref())
        .find_session(&token)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn oauth2_callback_redirects_new_user_to_new_user_callback_url() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(adapter, oauth_plugin(oauth_flow_config("oauth-user-2")));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", Some("/welcome"), false)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), Some("/welcome"));
}

#[tokio::test]
async fn oauth2_callback_redirects_signup_disabled_error() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = oauth_flow_config("oauth-user-3");
    config.disable_implicit_sign_up = true;
    let context = context_with_plugin(adapter, oauth_plugin(config));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=signup_disabled")
    );
}

#[tokio::test]
async fn oauth2_callback_redirects_provider_missing_email_error() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = oauth_flow_config("oauth-user-missing-email");
    config.get_user_info = Some(Arc::new(|_tokens| {
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id: "oauth-user-missing-email".to_owned(),
                name: Some("Ada Lovelace".to_owned()),
                email: None,
                image: None,
                email_verified: false,
            }))
        })
    }));
    let context = context_with_plugin(adapter, oauth_plugin(config));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=user_info_is_missing")
    );
}

#[tokio::test]
async fn oauth2_callback_allows_request_signup_when_implicit_signup_is_disabled() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = oauth_flow_config("oauth-user-4");
    config.disable_implicit_sign_up = true;
    let context = context_with_plugin(adapter, oauth_plugin(config));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", None, true)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), Some("/dashboard"));
}

#[tokio::test]
async fn oauth2_callback_uses_custom_redirect_uri_in_token_exchange() {
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let mut config = oauth_flow_config("oauth-user-5");
    config.redirect_uri = Some("https://app.example.com/custom/oauth/callback".to_owned());
    config.get_token = Some({
        let seen = Arc::clone(&seen);
        Arc::new(move |request: GenericOAuthTokenRequest| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                *seen.lock().unwrap() = request.redirect_uri;
                Ok(OAuth2Tokens {
                    access_token: Some("access-token".to_owned()),
                    ..OAuth2Tokens::default()
                })
            })
        })
    });
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(adapter, oauth_plugin(config));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let sign_in = sign_in_url(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();
    assert_eq!(
        query_value(&sign_in, "redirect_uri"),
        Some("https://app.example.com/custom/oauth/callback".to_owned())
    );
    let state = query_value(&sign_in, "state").unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        seen.lock().unwrap().as_str(),
        "https://app.example.com/custom/oauth/callback"
    );
}

#[tokio::test]
async fn oauth2_callback_applies_dynamic_token_url_params() {
    let body = Arc::new(Mutex::new(String::new()));
    let token_url = capture_post_server(
        Arc::clone(&body),
        r#"{"access_token":"access-token","token_type":"Bearer"}"#,
    );
    let mut config = example_config();
    config.token_url = Some(token_url);
    config
        .token_url_params
        .insert("resource".to_owned(), "static".to_owned());
    config.token_url_params_callback = Some(Arc::new(|context: GenericOAuthParamsContext| {
        Box::pin(async move {
            assert_eq!(context.provider_id, "example");
            assert_eq!(context.flow, GenericOAuthFlow::Callback);
            Ok(BTreeMap::from([
                ("resource".to_owned(), "dynamic".to_owned()),
                ("audience".to_owned(), "api".to_owned()),
            ]))
        })
    }));
    config.get_user_info = Some(Arc::new(|_tokens| {
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id: "oauth-user-token-params".to_owned(),
                name: Some("Ada Lovelace".to_owned()),
                email: Some("ada@example.com".to_owned()),
                image: None,
                email_verified: true,
            }))
        })
    }));
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(adapter, oauth_plugin(config));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    let posted = body.lock().unwrap().clone();
    assert!(posted.contains("resource=dynamic"));
    assert!(posted.contains("audience=api"));
}

#[tokio::test]
async fn oauth2_callback_uses_http_token_userinfo_and_authorization_headers() {
    let token_request = Arc::new(Mutex::new(String::new()));
    let userinfo_request = Arc::new(Mutex::new(String::new()));
    let token_url = capture_post_server(
        Arc::clone(&token_request),
        r#"{"access_token":"access-token","token_type":"Bearer"}"#,
    );
    let user_info_url = capture_get_server(
        Arc::clone(&userinfo_request),
        r#"{"sub":"http-user","email":"ada@example.com","email_verified":true,"name":"Ada HTTP","picture":"https://img.example.com/http.png"}"#,
    );
    let mut config = example_config();
    config.token_url = Some(token_url);
    config.user_info_url = Some(user_info_url);
    config
        .authorization_headers
        .insert("x-idp-header".to_owned(), "secret".to_owned());
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(adapter.clone(), oauth_plugin(config));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = sign_in_state(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    let posted = token_request.lock().unwrap().clone();
    assert!(posted.contains("x-idp-header: secret"));
    assert!(posted.contains("code=code-1"));
    assert!(userinfo_request
        .lock()
        .unwrap()
        .contains("authorization: Bearer access-token"));
    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_email("ada@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.name, "Ada HTTP");
}

#[tokio::test]
async fn oauth2_callback_rejects_missing_state() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let context = context_with_plugin(adapter, oauth_plugin(oauth_flow_config("oauth-user-6")));
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("https://app.example.com/api/auth/oauth2/callback/example?code=code-1")
                .body(Vec::new())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=invalid_state")
    );
}

#[tokio::test]
async fn sign_in_oauth2_caches_discovery_by_provider() {
    let hits = Arc::new(AtomicUsize::new(0));
    let discovery_url = discovery_server(Arc::clone(&hits));
    let mut config =
        GenericOAuthConfig::discovery("discovery", "client-1", Some("secret-1"), discovery_url);
    config.scopes = vec!["openid".to_owned()];
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![config],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();

    for _ in 0..2 {
        let response = router
            .handle_async(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://app.example.com/api/auth/sign-in/oauth2")
                    .header("content-type", "application/json")
                    .body(br#"{"providerId":"discovery","disableRedirect":true}"#.to_vec())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oauth2_callback_rejects_issuer_mismatch() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.issuer = Some("https://issuer.example.com".to_owned());
    config.require_issuer_validation = true;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![config],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let sign_in = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(
                    br#"{"providerId":"example","callbackURL":"/dashboard","errorCallbackURL":"/oauth-error","disableRedirect":true}"#
                        .to_vec(),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(sign_in.body()).unwrap();
    let auth_url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = query_value(&auth_url, "state").unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri(format!("https://app.example.com/api/auth/oauth2/callback/example?code=code-1&state={state}&iss=https%3A%2F%2Fwrong.example.com"))
                .body(Vec::new())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok()),
        Some("/oauth-error?error=issuer_mismatch")
    );
}

#[tokio::test]
async fn oauth2_callback_rejects_missing_required_issuer() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.issuer = Some("https://issuer.example.com".to_owned());
    config.require_issuer_validation = true;
    let context = context_with_plugin(
        adapter,
        generic_oauth(GenericOAuthOptions {
            config: vec![config],
        }),
    );
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let sign_in = sign_in_url(&router, "example", "/dashboard", None, false)
        .await
        .unwrap();
    let state = query_value(&sign_in, "state").unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=issuer_missing")
    );
}

#[tokio::test]
async fn oauth2_callback_appends_error_to_error_callback_url_with_query() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.issuer = Some("https://issuer.example.com".to_owned());
    config.require_issuer_validation = true;
    let context = context_with_plugin(
        adapter,
        generic_oauth(GenericOAuthOptions {
            config: vec![config],
        }),
    );
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let sign_in = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(
                    br#"{"providerId":"example","callbackURL":"/dashboard","errorCallbackURL":"/oauth-error?from=oauth","disableRedirect":true}"#
                        .to_vec(),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(sign_in.body()).unwrap();
    let auth_url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = query_value(&auth_url, "state").unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri(format!("https://app.example.com/api/auth/oauth2/callback/example?code=code-1&state={state}&iss=https%3A%2F%2Fwrong.example.com"))
                .body(Vec::new())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("/oauth-error?from=oauth&error=issuer_mismatch")
    );
}

#[tokio::test]
async fn oauth2_link_requires_session() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/oauth2/link")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"example","callbackURL":"/settings"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "SESSION_REQUIRED");
}

#[tokio::test]
async fn oauth2_link_creates_account_for_current_user() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    seed_user(adapter.as_ref(), "user_1", "ada@example.com").await;
    let context = context_with_plugin(adapter.clone(), oauth_plugin(oauth_flow_config("linked-1")));
    let cookie = session_cookie_for(adapter.as_ref(), &context, "user_1").await;
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = link_state(&router, "example", &cookie).await.unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(DbUserStore::new(adapter.as_ref())
        .find_account_by_provider_account("linked-1", "example")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn oauth2_link_rejects_account_owned_by_different_user() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    seed_user(adapter.as_ref(), "user_1", "ada@example.com").await;
    seed_user(adapter.as_ref(), "user_2", "grace@example.com").await;
    DbUserStore::new(adapter.as_ref())
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: "example".to_owned(),
            account_id: "linked-2".to_owned(),
            user_id: "user_2".to_owned(),
            access_token: Some("old-token".to_owned()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await
        .unwrap();
    let context = context_with_plugin(adapter.clone(), oauth_plugin(oauth_flow_config("linked-2")));
    let cookie = session_cookie_for(adapter.as_ref(), &context, "user_1").await;
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = link_state(&router, "example", &cookie).await.unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=account_already_linked_to_different_user")
    );
}

#[tokio::test]
async fn oauth2_link_rejects_email_mismatch() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    seed_user(adapter.as_ref(), "user_1", "ada@example.com").await;
    let mut config = oauth_flow_config("linked-email-mismatch");
    config.get_user_info = Some(Arc::new(|_tokens| {
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id: "linked-email-mismatch".to_owned(),
                name: Some("Grace Hopper".to_owned()),
                email: Some("grace@example.com".to_owned()),
                image: None,
                email_verified: true,
            }))
        })
    }));
    let context = context_with_plugin(adapter.clone(), oauth_plugin(config));
    let cookie = session_cookie_for(adapter.as_ref(), &context, "user_1").await;
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = link_state(&router, "example", &cookie).await.unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("https://app.example.com/error?error=email_doesn%27t_match")
    );
}

#[tokio::test]
async fn oauth2_link_updates_existing_account_for_same_user() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    seed_user(adapter.as_ref(), "user_1", "ada@example.com").await;
    DbUserStore::new(adapter.as_ref())
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: "example".to_owned(),
            account_id: "linked-update".to_owned(),
            user_id: "user_1".to_owned(),
            access_token: Some("old-token".to_owned()),
            refresh_token: Some("old-refresh".to_owned()),
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await
        .unwrap();
    let context = context_with_plugin(
        adapter.clone(),
        oauth_plugin(oauth_flow_config("linked-update")),
    );
    let cookie = session_cookie_for(adapter.as_ref(), &context, "user_1").await;
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let state = link_state(&router, "example", &cookie).await.unwrap();

    let response = oauth_callback(&router, "example", "code-1", &state)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    let account = DbUserStore::new(adapter.as_ref())
        .find_account_by_provider_account("linked-update", "example")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.user_id, "user_1");
    assert_eq!(account.access_token.as_deref(), Some("access-token"));
    assert_eq!(account.refresh_token.as_deref(), Some("refresh-token"));
}
