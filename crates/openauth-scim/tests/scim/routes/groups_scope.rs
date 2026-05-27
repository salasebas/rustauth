//! Organization-scoped provider requirement for SCIM Groups.

use super::*;

#[tokio::test]
async fn personal_scim_provider_rejects_all_group_routes() {
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

    for (method, path, body) in [
        (Method::GET, "/scim/v2/Groups", None),
        (
            Method::POST,
            "/scim/v2/Groups",
            Some(r#"{"displayName":"Personal Group"}"#),
        ),
        (
            Method::POST,
            "/scim/v2/Groups/.search",
            Some(r#"{"filter":"displayName co \"Personal\""}"#),
        ),
    ] {
        let response = match body {
            Some(body) => json_request(method.clone(), path, body, Some(&token)),
            None => auth_request(method.clone(), path, &token),
        };
        let response = router
            .handle_async(response)
            .await
            .expect("request should succeed");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{method} {path} should require org-scoped provider"
        );
        let body = json_body(response);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            body["detail"],
            "Groups require an organization-scoped SCIM provider"
        );
    }
}

#[tokio::test]
async fn personal_scim_provider_rejects_group_item_mutations() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "groups-scope-org@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");
    let org_token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &org_token, "Org Group", "org-group", &[]).await;

    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "personal".to_owned(),
            scim_token: "personal-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let personal_token = encode_bearer_token("personal-token", "personal", None);

    for (method, path, body) in [
        (
            Method::GET,
            format!("/scim/v2/Groups/{group_id}"),
            None,
        ),
        (
            Method::PUT,
            format!("/scim/v2/Groups/{group_id}"),
            Some(r#"{"displayName":"Nope"}"#.to_owned()),
        ),
        (
            Method::PATCH,
            format!("/scim/v2/Groups/{group_id}"),
            Some(
                r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Nope"}]}"#
                    .to_owned(),
            ),
        ),
        (
            Method::DELETE,
            format!("/scim/v2/Groups/{group_id}"),
            None,
        ),
    ] {
        let response = match body {
            Some(body) => json_request(method.clone(), &path, &body, Some(&personal_token)),
            None => auth_request(method.clone(), &path, &personal_token),
        };
        let response = router
            .handle_async(response)
            .await
            .expect("request should succeed");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{method} {path} with personal token"
        );
        assert_eq!(
            json_body(response)["detail"],
            "Groups require an organization-scoped SCIM provider"
        );
    }
}
