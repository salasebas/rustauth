use super::*;

#[tokio::test]
async fn org_scoped_management_requires_admin_or_owner_and_provisions_membership() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    let (member_cookie, _member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "member@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &admin_id, "admin")
        .await
        .expect("admin member");
    seed_member(adapter.as_ref(), "org_1", &_member_id, "member")
        .await
        .expect("regular member");

    let denied = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let member_list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(member_list.status(), StatusCode::OK);
    assert_eq!(
        json_body(member_list)["providers"]
            .as_array()
            .expect("providers should be array")
            .len(),
        0
    );

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"new-org-user","emails":[{"value":"new-org-user@example.com"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
    let user_id = json_body(created)["id"]
        .as_str()
        .expect("id should be string")
        .to_owned();

    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String("org_1".to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id))),
        )
        .await
        .expect("member lookup should succeed");
    assert!(member.is_some());
}

#[tokio::test]
async fn org_scoped_user_lists_are_isolated_by_organization() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    for org_id in ["org_a", "org_b"] {
        seed_organization(adapter.as_ref(), org_id)
            .await
            .expect("org should seed");
        seed_member(adapter.as_ref(), org_id, &admin_id, "admin")
            .await
            .expect("admin member should seed");
    }

    let token_a = generate_scim_token(&router, &admin_cookie, "provider-a", Some("org_a")).await;
    let token_b = generate_scim_token(&router, &admin_cookie, "provider-b", Some("org_b")).await;

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"org-a-user@example.com"}"#,
            Some(&token_a),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);

    let org_a = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token_a))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(org_a)["totalResults"], 1);

    let org_b = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token_b))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(org_b)["totalResults"], 0);
}

#[tokio::test]
async fn org_scoped_provider_cannot_be_replaced_by_omitting_organization_id() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &admin_id, "admin")
        .await
        .expect("admin member");

    let org_token = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(org_token.status(), StatusCode::CREATED);

    let personal_replace = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(personal_replace.status(), StatusCode::FORBIDDEN);

    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should still exist");
    assert_eq!(provider.organization_id.as_deref(), Some("org_1"));
}

#[tokio::test]
async fn org_scoped_provider_creator_loses_access_after_member_removal() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &admin_id, "admin")
        .await
        .expect("admin member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    remove_member(adapter.as_ref(), "org_1", &admin_id)
        .await
        .expect("member should remove");

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=okta",
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::FORBIDDEN);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(
        json_body(list)["providers"]
            .as_array()
            .expect("providers should be array")
            .len(),
        0
    );
}

#[tokio::test]
async fn org_scoped_management_allows_any_member_when_required_role_is_empty() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        required_role: Some(Vec::new()),
        ..ScimOptions::default()
    })
    .expect("router");
    let (member_cookie, member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "member@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &member_id, "member")
        .await
        .expect("regular member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(generated.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn org_scoped_management_accepts_custom_required_role_from_comma_separated_member_roles() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        required_role: Some(vec!["scim-admin".to_owned()]),
        ..ScimOptions::default()
    })
    .expect("router");
    let (member_cookie, member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "scim-admin@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &member_id, "viewer, scim-admin")
        .await
        .expect("member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(json_body(list)["providers"][0]["providerId"], "okta");
}

#[tokio::test]
async fn org_scoped_management_allows_admin_member_comma_separated_role() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "multi-role-owner@example.com")
            .await
            .expect("owner session");
    let (member_cookie, member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "multi-role-member@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    seed_member(adapter.as_ref(), "org_1", &member_id, "admin,member")
        .await
        .expect("multi-role member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"multi-role-provider","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(
        json_body(list)["providers"][0]["providerId"],
        "multi-role-provider"
    );

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=multi-role-provider",
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(json_body(get)["providerId"], "multi-role-provider");

    let (plain_member_cookie, plain_member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "plain-member@example.com")
            .await
            .expect("plain member session");
    seed_member(adapter.as_ref(), "org_1", &plain_member_id, "member")
        .await
        .expect("plain member");

    let denied = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"ghsa-member-attempt","organizationId":"org_1"}"#,
            &plain_member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let _ = owner_cookie;
}

#[tokio::test]
async fn org_scoped_management_uses_custom_organization_creator_role_by_default() {
    let (adapter, router, context) = router_with_context_and_organization_options(
        ScimOptions::default(),
        OrganizationOptions::builder()
            .creator_role("creator")
            .build(),
    )
    .expect("router");
    let (creator_cookie, creator_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "creator@example.com")
            .await
            .expect("creator session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &creator_id, "creator")
        .await
        .expect("creator member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &creator_cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(generated.status(), StatusCode::CREATED);
}
