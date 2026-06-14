use super::*;

#[tokio::test]
async fn management_default_token_storage_hashes_persisted_token() {
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let decoded = rustauth_scim::token::decode_bearer_token(token).expect("token should decode");
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should exist");
    assert_eq!(
        provider.scim_token,
        rustauth_scim::token::hash_base_token(&decoded.base_token)
    );
    assert_ne!(provider.scim_token, decoded.base_token);
}

#[tokio::test]
async fn management_regenerating_token_preserves_provider_id() {
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");

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
        ..crate::scim_options_for_global_management()
    })
    .await;
}

#[tokio::test]
async fn management_encrypted_token_storage_can_authenticate_generated_token() {
    generated_token_can_provision_user_with_options(ScimOptions {
        token_storage: ScimTokenStorage::Encrypted,
        ..crate::scim_options_for_global_management()
    })
    .await;
}

#[tokio::test]
async fn management_custom_hash_token_storage_can_authenticate_generated_token() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        token_storage: ScimTokenStorage::custom_hash(|token| {
            Box::pin(async move { Ok(format!("{token}:hashed")) })
        }),
        ..crate::scim_options_for_global_management()
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
        ..crate::scim_options_for_global_management()
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
        ..crate::scim_options_for_global_management()
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
        ..crate::scim_options_for_global_management()
    })
    .expect("router");
    let (cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "owner@example.com")
            .await
            .expect("session cookie should create");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "existing-token".to_owned(),
            organization_id: None,
            user_id: Some(owner_id),
        })
        .await
        .expect("provider should create");

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
    assert_eq!(json_body(response)["message"], "blocked replacement");
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
        ..crate::scim_options_for_global_management()
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
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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

#[tokio::test]
async fn management_global_requires_provider_ownership_for_generate() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
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
    assert_eq!(
        json_body(response)["message"],
        "Global SCIM provider management requires provider ownership to be enabled"
    );
}

#[tokio::test]
async fn management_delete_provider_purges_users_and_blocks_provider_id_reuse() {
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let first_token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    let user_id = create_scim_user(
        &router,
        &first_token,
        "reused-provider@example.com",
        "Reused Provider",
    )
    .await;

    let deleted = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::OK);

    let old_token_response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &first_token))
        .await
        .expect("request should succeed");
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let regenerated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(regenerated.status(), StatusCode::CREATED);
    let second_token = json_body(regenerated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    assert_ne!(first_token, second_token);

    let listed = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &second_token))
        .await
        .expect("request should succeed");
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(json_body(listed)["totalResults"], 0);

    let stale_user = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &second_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(stale_user.status(), StatusCode::NOT_FOUND);

    let profile = adapter
        .find_one(
            FindOne::new("scim_user_profile")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String("okta".to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.clone()))),
        )
        .await
        .expect("profile lookup should succeed");
    assert!(profile.is_none());

    let account = adapter
        .find_one(
            FindOne::new("account")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String("okta".to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id))),
        )
        .await
        .expect("account lookup should succeed");
    assert!(account.is_none());
}

#[tokio::test]
async fn management_delete_provider_purges_groups_without_touching_native_teams() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_global_management())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");

    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id = create_scim_user(&router, &token, "group-purge@example.com", "Group Purge").await;
    let scim_group_id =
        create_scim_group(&router, &token, "SCIM Group", "scim-group", &[&user_id]).await;

    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("team")
                .data("id", DbValue::String("native_team_1".to_owned()))
                .data("name", DbValue::String("Native Team".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await
        .expect("native team should create");

    let deleted = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"okta"}"#,
            &owner_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::OK);

    let native_team = adapter
        .find_one(FindOne::new("team").where_clause(Where::new(
            "id",
            DbValue::String("native_team_1".to_owned()),
        )))
        .await
        .expect("native team lookup should succeed");
    assert!(native_team.is_some());

    let scim_team = adapter
        .find_one(
            FindOne::new("team").where_clause(Where::new("id", DbValue::String(scim_group_id))),
        )
        .await
        .expect("scim team lookup should succeed");
    assert!(scim_team.is_none());

    let scim_profile = adapter
        .find_one(FindOne::new("scim_group_profile").where_clause(Where::new(
            "provider_id",
            DbValue::String("okta".to_owned()),
        )))
        .await
        .expect("group profile lookup should succeed");
    assert!(scim_profile.is_none());

    let second_token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let listed = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Groups", &second_token))
        .await
        .expect("request should succeed");
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(json_body(listed)["totalResults"], 0);
}

#[tokio::test]
async fn management_delete_provider_does_not_touch_other_providers() {
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    for provider_id in ["okta", "entra"] {
        router
            .handle_async(session_json_request(
                Method::POST,
                "/scim/generate-token",
                &format!(r#"{{"providerId":"{provider_id}"}}"#),
                &cookie,
            ))
            .await
            .expect("request should succeed");
    }

    let okta_token = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    let okta_token = json_body(okta_token)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    let entra_token = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"entra"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    let entra_token = json_body(entra_token)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let okta_user_id =
        create_scim_user(&router, &okta_token, "okta-only@example.com", "Okta Only").await;
    let entra_user_id = create_scim_user(
        &router,
        &entra_token,
        "entra-only@example.com",
        "Entra Only",
    )
    .await;

    let deleted = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::OK);

    let entra_list = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &entra_token))
        .await
        .expect("request should succeed");
    assert_eq!(entra_list.status(), StatusCode::OK);
    assert_eq!(json_body(entra_list)["totalResults"], 1);

    let entra_user = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{entra_user_id}"),
            &entra_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(entra_user.status(), StatusCode::OK);

    let stale_okta_user = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{okta_user_id}"),
            &entra_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(stale_okta_user.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn management_delete_provider_unlinks_linked_user_when_other_accounts_exist() {
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
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
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let existing = DbUserStore::new(adapter.as_ref())
        .create_user(
            CreateUserInput::new("Password User", "linked-delete@example.com").email_verified(true),
        )
        .await
        .expect("user should create");
    DbUserStore::new(adapter.as_ref())
        .create_credential_account(CreateCredentialAccountInput::new(
            &existing.id,
            "hashed-password".to_owned(),
        ))
        .await
        .expect("credential account should create");

    let linked = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"linked-delete@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(linked.status(), StatusCode::CREATED);

    let deleted = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::OK);

    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&existing.id)
        .await
        .expect("lookup should succeed")
        .expect("user should remain");
    assert_eq!(user.email, "linked-delete@example.com");

    let accounts = DbUserStore::new(adapter.as_ref())
        .list_accounts_for_user(&existing.id)
        .await
        .expect("accounts should list");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id, "credential");
}

#[tokio::test]
async fn management_global_unowned_provider_is_inaccessible_with_ownership() {
    let (adapter, router, context) =
        router_with_context(crate::scim_options_for_global_management()).expect("router");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "legacy-okta".to_owned(),
            scim_token: "legacy-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    assert!(json_body(list)["providers"]
        .as_array()
        .expect("providers should be array")
        .is_empty());

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=legacy-okta",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::FORBIDDEN);
}
