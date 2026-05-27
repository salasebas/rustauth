//! SCIM isolation and auth-boundary tests (parity gaps vs upstream coverage).

use super::*;

#[tokio::test]
async fn user_item_routes_return_not_found_for_other_providers_user() {
    let (adapter, router) = router_with_adapter().expect("router should build");
    for (provider_id, base_token) in [("okta", "okta-secret"), ("entra", "entra-secret")] {
        ScimProviderStore::new(adapter.as_ref())
            .create(CreateScimProviderInput {
                provider_id: provider_id.to_owned(),
                scim_token: base_token.to_owned(),
                organization_id: None,
                user_id: None,
            })
            .await
            .expect("provider should create");
    }
    let okta_token = encode_bearer_token("okta-secret", "okta", None);
    let entra_token = encode_bearer_token("entra-secret", "entra", None);
    let user_id = create_scim_user(
        &router,
        &entra_token,
        "isolated-item@example.com",
        "Isolated Item",
    )
    .await;

    for (method, path, body) in [
        (
            Method::GET,
            format!("/scim/v2/Users/{user_id}"),
            None,
        ),
        (
            Method::PUT,
            format!("/scim/v2/Users/{user_id}"),
            Some(
                r#"{"userName":"isolated-item@example.com","emails":[{"value":"isolated-item@example.com"}]}"#
                    .to_owned(),
            ),
        ),
        (
            Method::PATCH,
            format!("/scim/v2/Users/{user_id}"),
            Some(
                r#"{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations":[{"op":"replace","path":"name.formatted","value":"Nope"}]
                }"#
                .to_owned(),
            ),
        ),
        (
            Method::DELETE,
            format!("/scim/v2/Users/{user_id}"),
            None,
        ),
    ] {
        let response = match body {
            Some(body) => {
                json_request(method.clone(), &path, &body, Some(&okta_token))
            }
            None => auth_request(method.clone(), &path, &okta_token),
        };
        let response = router
            .handle_async(response)
            .await
            .expect("request should succeed");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{method} {path} should not expose other provider user"
        );
    }

    let still_there = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &entra_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(still_there.status(), StatusCode::OK);
}

#[tokio::test]
async fn scim_auth_rejects_bearer_when_encoded_organization_does_not_match_provider_row() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "token-org-mismatch@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_stored")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_stored", &owner_id, "owner")
        .await
        .expect("member");

    let stored_token =
        generate_scim_token(&router, &owner_cookie, "okta", Some("org_stored")).await;
    let decoded = openauth_scim::token::decode_bearer_token(&stored_token).expect("decode");
    let wrong_org_token =
        encode_bearer_token(&decoded.base_token, &decoded.provider_id, Some("org_other"));

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"token-org-mismatch-user@example.com"}"#,
            Some(&wrong_org_token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)["detail"], "Invalid SCIM token");
}

#[tokio::test]
async fn org_scoped_get_user_returns_not_found_for_user_in_other_organization() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "org-get-isolation-owner@example.com",
    )
    .await
    .expect("owner session");
    for org_id in ["org_a", "org_b"] {
        seed_organization(adapter.as_ref(), org_id)
            .await
            .expect("org");
        seed_member(adapter.as_ref(), org_id, &owner_id, "owner")
            .await
            .expect("member");
    }
    let token_a = generate_scim_token(&router, &owner_cookie, "okta-org-a", Some("org_a")).await;
    let token_b = generate_scim_token(&router, &owner_cookie, "okta-org-b", Some("org_b")).await;
    let user_id = create_scim_user(&router, &token_b, "org-b-only@example.com", "Org B Only").await;

    let response = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token_a,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn users_route_put_rejects_duplicate_external_id_for_same_provider() {
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

    let first_id = create_scim_user(&router, &token, "first-dup@example.com", "First Dup").await;
    let second_id = create_scim_user(&router, &token, "second-dup@example.com", "Second Dup").await;

    let response = router
        .handle_async(json_request(
            Method::PUT,
            &format!("/scim/v2/Users/{second_id}"),
            r#"{
                "userName":"second-dup@example.com",
                "externalId":"first-dup@example.com",
                "emails":[{"value":"second-dup@example.com"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(response)["scimType"], "uniqueness");

    let first = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{first_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(first)["externalId"], "first-dup@example.com");
}

#[tokio::test]
async fn users_route_patch_rejects_duplicate_external_id_for_same_provider() {
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

    let _first_id =
        create_scim_user(&router, &token, "patch-first@example.com", "Patch First").await;
    let second_id =
        create_scim_user(&router, &token, "patch-second@example.com", "Patch Second").await;

    let response = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{second_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"externalId","value":"patch-first@example.com"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(response)["scimType"], "uniqueness");
}

#[tokio::test]
async fn org_scoped_groups_are_visible_across_providers_in_same_organization() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "group-shared-org@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");

    let okta_token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let entra_token = generate_scim_token(&router, &owner_cookie, "entra", Some("org_1")).await;
    let group_id = create_scim_group(
        &router,
        &entra_token,
        "Shared Org Group",
        "shared-group",
        &[],
    )
    .await;

    let okta_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &okta_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(okta_get.status(), StatusCode::OK);
    assert_eq!(json_body(okta_get)["displayName"], "Shared Org Group");

    let okta_list = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Groups", &okta_token))
        .await
        .expect("request should succeed");
    let list_body = json_body(okta_list);
    assert_eq!(list_body["totalResults"], 1);
    assert_eq!(list_body["Resources"][0]["id"], group_id);
}
