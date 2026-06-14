//! Bearer authentication for SCIM Group routes (parity with `routes/auth.rs` for Users).

use super::*;

#[tokio::test]
async fn groups_route_requires_valid_bearer_token() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "groups-auth-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &token, "Auth Group", "auth-group", &[]).await;

    let missing = router
        .handle_async(request(Method::GET, "/scim/v2/Groups"))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(missing)["detail"], "SCIM token is required");

    let invalid = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            "not-base64",
        ))
        .await
        .expect("request should succeed");
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(invalid)["detail"], "Invalid SCIM token");
}

#[tokio::test]
async fn all_group_routes_reject_missing_and_invalid_bearer_tokens() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "groups-auth-routes@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &token, "Routes Group", "routes-group", &[]).await;

    let cases = [
        (Method::GET, "/scim/v2/Groups", None),
        (
            Method::POST,
            "/scim/v2/Groups",
            Some(r#"{"displayName":"New Group"}"#),
        ),
        (Method::GET, &format!("/scim/v2/Groups/{group_id}"), None),
        (
            Method::PUT,
            &format!("/scim/v2/Groups/{group_id}"),
            Some(r#"{"displayName":"Updated"}"#),
        ),
        (
            Method::PATCH,
            &format!("/scim/v2/Groups/{group_id}"),
            Some(
                r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Patched"}]}"#,
            ),
        ),
        (Method::DELETE, &format!("/scim/v2/Groups/{group_id}"), None),
    ];

    for (method, path, body) in cases {
        let missing = match body {
            Some(body) => json_request(method.clone(), path, body, None),
            None => request(method.clone(), path),
        };
        let missing = router
            .handle_async(missing)
            .await
            .expect("request should succeed");
        let missing_status = missing.status();
        assert_eq!(
            missing_status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} missing bearer"
        );

        let invalid = match body {
            Some(body) => json_request(method.clone(), path, body, Some("not-base64")),
            None => auth_request(method.clone(), path, "not-base64"),
        };
        let invalid = router
            .handle_async(invalid)
            .await
            .expect("request should succeed");
        assert_eq!(
            invalid.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} invalid bearer"
        );
    }
}

#[tokio::test]
async fn groups_route_accepts_case_insensitive_bearer_scheme_and_header_name() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "groups-auth-case@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("/scim/v2/Groups")
                .header("authorization", format!("bearer {token}"))
                .body(Vec::new())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
}
