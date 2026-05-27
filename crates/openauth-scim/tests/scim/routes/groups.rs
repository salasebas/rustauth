use super::*;

#[tokio::test]
async fn groups_route_creates_lists_and_returns_team_backed_groups() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
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

    let created_user = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"member@example.com","name":{"formatted":"Member One"}}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created_user.status(), StatusCode::CREATED);
    let user_id = json_body(created_user)["id"]
        .as_str()
        .expect("user id")
        .to_owned();

    let created_group = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Groups",
            &format!(
                r#"{{"displayName":"Engineering","externalId":"eng","members":[{{"value":"{user_id}"}}]}}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created_group.status(), StatusCode::CREATED);
    assert_eq!(
        created_group.headers().get(header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/scim+json"))
    );
    let group = json_body(created_group);
    assert_eq!(
        group["schemas"][0],
        "urn:ietf:params:scim:schemas:core:2.0:Group"
    );
    assert_eq!(group["displayName"], "Engineering");
    assert_eq!(group["externalId"], "eng");
    assert_eq!(group["members"][0]["value"], user_id);
    assert_eq!(group["members"][0]["display"], "Member One");
    let group_id = group["id"].as_str().expect("group id").to_owned();

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
    assert_eq!(json_body(fetched)["members"][0]["value"], user_id);

    let listed = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Groups", &token))
        .await
        .expect("request should succeed");
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed);
    assert_eq!(listed["totalResults"], 1);
    assert_eq!(listed["Resources"][0]["id"], group_id);
}

#[tokio::test]
async fn groups_route_replaces_patches_and_deletes_team_backed_groups() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "group-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let first_user_id = create_scim_user(&router, &token, "first@example.com", "First User").await;
    let second_user_id =
        create_scim_user(&router, &token, "second@example.com", "Second User").await;
    let group_id = create_scim_group(
        &router,
        &token,
        "Engineering",
        "eng",
        &[first_user_id.as_str()],
    )
    .await;

    let put = router
        .handle_async(json_request(
            Method::PUT,
            &format!("/scim/v2/Groups/{group_id}"),
            &format!(
                r#"{{"displayName":"Platform","externalId":"platform","members":[{{"value":"{second_user_id}"}}]}}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::OK);
    let put_body = json_body(put);
    assert_eq!(put_body["displayName"], "Platform");
    assert_eq!(put_body["externalId"], "platform");
    assert_eq!(put_body["members"].as_array().expect("members").len(), 1);
    assert_eq!(put_body["members"][0]["value"], second_user_id);

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations":[
                        {{"op":"replace","path":"displayName","value":"Identity"}},
                        {{"op":"add","path":"members","value":[{{"value":"{first_user_id}"}}]}},
                        {{"op":"remove","path":"members[value eq \"{second_user_id}\"]"}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::OK);
    let patch_body = json_body(patch);
    assert_eq!(patch_body["displayName"], "Identity");
    assert_eq!(patch_body["members"].as_array().expect("members").len(), 1);
    assert_eq!(patch_body["members"][0]["value"], first_user_id);

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let missing = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn groups_put_rejects_unknown_members_without_replacing_membership() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "groups-put-invalid-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id = create_scim_user(
        &router,
        &token,
        "groups-put-existing@example.com",
        "Existing",
    )
    .await;
    let group_id = create_scim_group(
        &router,
        &token,
        "PUT Unknown Members",
        "put-unknown",
        &[&user_id],
    )
    .await;

    let put = router
        .handle_async(json_request(
            Method::PUT,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{"displayName":"Should Not Replace","members":[{"value":"missing-user"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(put)["scimType"], "invalidValue");

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    let body = json_body(fetched);
    assert_eq!(body["displayName"], "PUT Unknown Members");
    assert_eq!(body["members"].as_array().expect("members").len(), 1);
    assert_eq!(body["members"][0]["value"], user_id);
}

#[tokio::test]
async fn groups_put_rejects_empty_display_name_without_replacing_group() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "groups-put-empty-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &token, "Named Group", "named-group", &[]).await;

    let put = router
        .handle_async(json_request(
            Method::PUT,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{"displayName":"   ","members":[]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(put)["scimType"], "invalidValue");

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(fetched)["displayName"], "Named Group");
}

#[tokio::test]
async fn groups_patch_replace_members_replaces_existing_membership() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "groups-replace-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let first_user_id =
        create_scim_user(&router, &token, "first-replace@example.com", "First").await;
    let second_user_id =
        create_scim_user(&router, &token, "second-replace@example.com", "Second").await;
    let group_id = create_scim_group(
        &router,
        &token,
        "Replace Members",
        "replace-members",
        &[&first_user_id],
    )
    .await;

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations":[
                        {{"op":"replace","path":"members","value":[{{"value":"{second_user_id}"}}]}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::OK);

    let body = json_body(patch);
    assert_eq!(body["members"].as_array().expect("members").len(), 1);
    assert_eq!(body["members"][0]["value"], second_user_id);
}

#[tokio::test]
async fn groups_patch_rejects_nested_groups_and_unknown_members() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "groups-invalid-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id =
        create_scim_group(&router, &token, "Invalid Members", "invalid-members", &[]).await;

    let nested = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"add","path":"members","value":[{"value":"group-1","type":"Group"}]}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(nested.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(nested)["scimType"], "invalidValue");

    let missing = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"add","path":"members","value":[{"value":"missing-user"}]}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(missing)["scimType"], "invalidValue");

    let empty_display_name = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"displayName","value":"   "}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(empty_display_name.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(empty_display_name)["scimType"], "invalidValue");

    let unsupported_path = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"externalId","value":"ignored"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(unsupported_path.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(unsupported_path)["scimType"], "invalidPath");

    let no_effect = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"remove","path":"displayName"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(no_effect.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(no_effect)["scimType"], "invalidPath");
}

#[tokio::test]
async fn groups_support_filter_sort_projection_and_etags() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "groups-search-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let first_id = create_scim_group(&router, &token, "Alpha Identity", "alpha", &[]).await;
    let second_id = create_scim_group(&router, &token, "Beta Finance", "beta", &[]).await;

    let list = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Groups?filter=displayName%20co%20%22Identity%22&attributes=displayName&sortBy=displayName&sortOrder=descending",
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let body = json_body(list);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["id"], first_id);
    assert_eq!(body["Resources"][0]["displayName"], "Alpha Identity");
    assert!(body["Resources"][0].get("members").is_none());

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{second_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
    let etag = fetched
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("etag string")
        .to_owned();

    let stale = router
        .handle_async(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/scim/v2/Groups/{second_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::IF_MATCH, r#"W/"stale""#)
                .body(br#"{"displayName":"Should Fail"}"#.to_vec())
                .expect("request"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

    let updated = router
        .handle_async(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/scim/v2/Groups/{second_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::IF_MATCH, etag)
                .body(br#"{"displayName":"Beta Updated"}"#.to_vec())
                .expect("request"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(updated.status(), StatusCode::OK);
    assert!(updated.headers().get(header::ETAG).is_some());
}
