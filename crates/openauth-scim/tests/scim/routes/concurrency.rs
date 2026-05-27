//! ETag / If-Match behavior (including wildcard acceptance).

use super::*;

#[tokio::test]
async fn user_put_and_patch_accept_if_match_wildcard() {
    let (adapter, router) = router_with_adapter().expect("router should build");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("base-token", "okta", None);
    let user_id = create_scim_user(&router, &token, "wildcard@example.com", "Wildcard User").await;

    let put = router
        .handle_async(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/scim/v2/Users/{user_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::IF_MATCH, "*")
                .body(br#"{"userName":"wildcard@example.com","name":{"formatted":"Wildcard Updated"}}"#.to_vec())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::OK);

    let patch = router
        .handle_async(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/scim/v2/Users/{user_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::IF_MATCH, "*")
                .body(
                    br#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"Engineer"}]}"#
                        .to_vec(),
                )
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(fetched)["title"], "Engineer");
}

#[tokio::test]
async fn group_put_and_patch_accept_if_match_wildcard() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "group-wildcard@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id =
        create_scim_group(&router, &token, "Wildcard Group", "wildcard-group", &[]).await;

    let put = router
        .handle_async(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/scim/v2/Groups/{group_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::IF_MATCH, "*")
                .body(br#"{"displayName":"Wildcard Updated"}"#.to_vec())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::OK);
    assert_eq!(json_body(put)["displayName"], "Wildcard Updated");

    let patch = router
        .handle_async(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/scim/v2/Groups/{group_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::IF_MATCH, "*")
                .body(
                    br#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Wildcard Patched"}]}"#
                        .to_vec(),
                )
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::OK);
    assert_eq!(json_body(patch)["displayName"], "Wildcard Patched");
}

#[tokio::test]
async fn user_delete_accepts_if_match_wildcard() {
    let (adapter, router) = router_with_adapter().expect("router should build");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("base-token", "okta", None);
    let user_id = create_scim_user(
        &router,
        &token,
        "delete-wildcard@example.com",
        "Delete Wildcard",
    )
    .await;

    let deleted = router
        .handle_async(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/scim/v2/Users/{user_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::IF_MATCH, "*")
                .body(Vec::new())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let missing = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}
