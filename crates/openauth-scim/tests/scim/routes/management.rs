use super::*;

#[tokio::test]
async fn management_default_token_storage_hashes_persisted_token() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");
    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let body = json_body(generated);
    let token = body["scimToken"].as_str().expect("token should be string");
    let decoded = openauth_scim::token::decode_bearer_token(token).expect("token should decode");
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should exist");
    assert_eq!(
        provider.scim_token,
        openauth_scim::token::hash_base_token(&decoded.base_token)
    );
    assert_ne!(provider.scim_token, decoded.base_token);
}

#[tokio::test]
async fn management_regenerating_token_preserves_provider_id() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");
    let first_token = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(first_token.status(), StatusCode::CREATED);
    let first_provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should exist");
    let first_stored_token = first_provider.scim_token.clone();

    let second_token = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(second_token.status(), StatusCode::CREATED);

    let second_provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should exist");
    assert_eq!(second_provider.id, first_provider.id);
    assert_ne!(second_provider.scim_token, first_stored_token);

    let providers = ScimProviderStore::new(adapter.as_ref())
        .list()
        .await
        .expect("list should succeed");
    assert_eq!(providers.len(), 1);
}

#[tokio::test]
async fn management_generate_token_requires_session_and_token_can_provision_users() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");

    let anonymous = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            "",
        ))
        .await
        .expect("request should succeed");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");
    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"scim-user","emails":[{"value":"scim@example.com"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn management_hashed_token_storage_can_authenticate_generated_token() {
    generated_token_can_provision_user_with_options(ScimOptions {
        token_storage: ScimTokenStorage::Hashed,
        ..ScimOptions::default()
    })
    .await;
}

#[tokio::test]
async fn management_encrypted_token_storage_can_authenticate_generated_token() {
    generated_token_can_provision_user_with_options(ScimOptions {
        token_storage: ScimTokenStorage::Encrypted,
        ..ScimOptions::default()
    })
    .await;
}

#[tokio::test]
async fn management_custom_hash_token_storage_can_authenticate_generated_token() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        token_storage: ScimTokenStorage::custom_hash(|token| {
            Box::pin(async move { Ok(format!("{token}:hashed")) })
        }),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should exist");
    assert!(provider.scim_token.ends_with(":hashed"));

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"custom-hash@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn management_custom_encryption_token_storage_can_authenticate_generated_token() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        token_storage: ScimTokenStorage::custom_encryption(
            |token| Box::pin(async move { Ok(token.chars().rev().collect()) }),
            |token| Box::pin(async move { Ok(token.chars().rev().collect()) }),
        ),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"custom-encryption@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn management_before_token_hook_failure_aborts_persistence() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let (adapter, router, context) = router_with_context(ScimOptions {
        before_token_generated: Some(Arc::new(move |input| {
            let calls = Arc::clone(&calls_for_hook);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(input.user.email, "owner@example.com");
                assert!(input.member.is_none());
                assert!(!input.scim_token.is_empty());
                Err(ScimHookError::forbidden("blocked by hook"))
            })
        })),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)["message"], "blocked by hook");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed");
    assert!(provider.is_none());
}

#[tokio::test]
async fn management_before_token_hook_failure_preserves_existing_provider() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        before_token_generated: Some(Arc::new(|_input| {
            Box::pin(async { Err(ScimHookError::forbidden("blocked replacement")) })
        })),
        ..ScimOptions::default()
    })
    .expect("router");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "existing-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("existing provider should be preserved");
    assert_eq!(provider.scim_token, "existing-token");
}

#[tokio::test]
async fn management_after_token_hook_receives_persisted_provider_and_returned_token() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let seen_token = Arc::new(std::sync::Mutex::new(String::new()));
    let seen_token_for_hook = Arc::clone(&seen_token);
    let (adapter, router, context) = router_with_context(ScimOptions {
        after_token_generated: Some(Arc::new(move |input| {
            let calls = Arc::clone(&calls_for_hook);
            let seen_token = Arc::clone(&seen_token_for_hook);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(input.provider.provider_id, "okta");
                assert_eq!(input.user.email, "owner@example.com");
                assert!(!input.provider.scim_token.is_empty());
                *seen_token.lock().expect("token mutex should lock") = input.scim_token;
                Ok(())
            })
        })),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    let returned_token = json_body(response)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        seen_token.lock().expect("token mutex should lock").as_str(),
        returned_token
    );
}

#[tokio::test]
async fn management_lists_gets_and_deletes_provider_connections() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        provider_ownership: openauth_scim::ProviderOwnershipOptions { enabled: true },
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    assert_eq!(list["providers"][0]["providerId"], "okta");
    assert!(list["providers"][0].get("scimToken").is_none());
    assert!(list["providers"][0].get("userId").is_none());

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=okta",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::OK);
    let get = json_body(get);
    assert_eq!(get["providerId"], "okta");
    assert!(get.get("scimToken").is_none());
    assert!(get.get("userId").is_none());

    let delete = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(json_body(delete)["success"], true);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(list)["providers"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn management_unknown_provider_get_and_delete_return_not_found() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=missing",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);

    let delete = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"missing"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn management_token_replacement_invalidates_previous_token() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let first = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_token = json_body(first)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let second = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(second.status(), StatusCode::CREATED);
    let second_token = json_body(second)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    assert_ne!(first_token, second_token);

    let old_token_response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &first_token))
        .await
        .expect("request should succeed");
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let new_token_response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &second_token))
        .await
        .expect("request should succeed");
    assert_eq!(new_token_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn management_generate_token_rejects_provider_ids_with_colons() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta:tenant"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn management_provider_ownership_blocks_other_users() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        provider_ownership: openauth_scim::ProviderOwnershipOptions { enabled: true },
        ..ScimOptions::default()
    })
    .expect("router");
    let owner_cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("owner session cookie should create");
    let other_cookie = session_cookie(adapter.as_ref(), &context, "other@example.com")
        .await
        .expect("other session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &owner_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=okta",
            &other_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::FORBIDDEN);

    let regenerate = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &other_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(regenerate.status(), StatusCode::FORBIDDEN);
}
