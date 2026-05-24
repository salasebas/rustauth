use super::*;

#[tokio::test]
async fn search_routes_return_filtered_users_groups_and_all_resources() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "search-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id = create_scim_user(&router, &token, "search-user@example.com", "Search User").await;
    create_scim_group(
        &router,
        &token,
        "Search Team",
        "search-team",
        &[user_id.as_str()],
    )
    .await;
    create_scim_group(&router, &token, "Other Team", "other-team", &[]).await;

    let users = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users/.search",
            r#"{"filter":"userName eq \"search-user@example.com\"","startIndex":1,"count":10}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(users.status(), StatusCode::OK);
    let users = json_body(users);
    assert_eq!(users["totalResults"], 1);
    assert_eq!(users["Resources"][0]["userName"], "search-user@example.com");

    let groups = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Groups/.search",
            r#"{"filter":"displayName co \"Search\""}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(groups.status(), StatusCode::OK);
    let groups = json_body(groups);
    assert_eq!(groups["totalResults"], 1);
    assert_eq!(groups["Resources"][0]["displayName"], "Search Team");

    let all = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/.search",
            r#"{"count":10}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(all.status(), StatusCode::OK);
    let all = json_body(all);
    assert_eq!(all["totalResults"], 3);
}

#[tokio::test]
async fn search_routes_return_scim_errors_for_invalid_json_bodies() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "search-json-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_search_json")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_search_json", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(
        &router,
        &owner_cookie,
        "okta-search-json",
        Some("org_search_json"),
    )
    .await;

    for path in [
        "/scim/v2/Users/.search",
        "/scim/v2/Groups/.search",
        "/scim/v2/.search",
    ] {
        let response = router
            .handle_async(json_request(
                Method::POST,
                path,
                r#"{"filter":"unterminated""#,
                Some(&token),
            ))
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&http::HeaderValue::from_static("application/scim+json")),
            "{path}"
        );
        let body = json_body(response);
        assert_eq!(body["schemas"][0], openauth_scim::errors::SCIM_ERROR_SCHEMA);
        assert!(body["detail"]
            .as_str()
            .expect("detail should be string")
            .contains("invalid JSON request body"));
    }
}
