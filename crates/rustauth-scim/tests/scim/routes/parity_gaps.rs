//! Regression tests for parity gaps documented in `crates/rustauth-scim/README.md`.

use super::*;

async fn seed_plain_provider(adapter: &dyn DbAdapter, provider_id: &str, base_token: &str) {
    ScimProviderStore::new(adapter)
        .create(CreateScimProviderInput {
            provider_id: provider_id.to_owned(),
            scim_token: base_token.to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
}

#[tokio::test]
async fn management_regenerate_rejects_different_organization_scope() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_global_management())
            .expect("router");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("organization");
    let (cookie, user_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "owner@example.com")
            .await
            .expect("session");
    seed_member(adapter.as_ref(), "org_1", &user_id, "admin")
        .await
        .expect("member");

    let _ = generate_scim_token(&router, &cookie, "okta", None).await;

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response)["message"],
        "SCIM provider exists for a different scope"
    );

    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("lookup")
        .expect("personal provider row should remain");
    assert!(provider.organization_id.is_none());
}

#[tokio::test]
async fn management_get_provider_connection_requires_provider_id() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session");

    let response = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection",
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)["message"], "providerId is required");
}

#[tokio::test]
async fn management_empty_required_role_allows_any_org_member() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        required_role: Some(Vec::new()),
        ..ScimOptions::default()
    })
    .expect("router");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("organization");
    let (member_cookie, member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "member@example.com")
            .await
            .expect("session");
    seed_member(adapter.as_ref(), "org_1", &member_id, "member")
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
}

#[tokio::test]
async fn users_create_with_given_and_family_name_parts() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{
                "userName":"juan.perez@example.com",
                "name":{"givenName":"Juan","familyName":"Perez"}
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response);
    assert_eq!(body["userName"], "juan.perez@example.com");
    assert_eq!(body["displayName"], "Juan Perez");
    assert_eq!(body["name"]["formatted"], "Juan Perez");
    assert_eq!(body["externalId"], "juan.perez@example.com");
}

#[tokio::test]
async fn users_create_with_primary_email_in_emails_array() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{
                "userName":"juan.perez@example.com",
                "name":{"formatted":"Juan Perez"},
                "emails":[
                    {"value":"secondary@example.com"},
                    {"value":"primary@example.com","primary":true}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response);
    assert_eq!(body["userName"], "primary@example.com");
    assert_eq!(body["emails"][0]["value"], "primary@example.com");
    assert!(body["emails"][0]["primary"].as_bool().unwrap_or(false));
}

#[tokio::test]
async fn users_create_with_external_id_uses_external_id_as_account_id() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{
                "userName":"juan.perez@example.com",
                "externalId":"external-username"
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response);
    assert_eq!(body["externalId"], "external-username");
    assert_eq!(body["userName"], "juan.perez@example.com");
}

#[tokio::test]
async fn users_create_sets_email_verified_on_new_user() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"verified@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    let user_id = json_body(response)["id"].as_str().expect("id").to_owned();

    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&user_id)
        .await
        .expect("lookup")
        .expect("user should exist");
    assert!(user.email_verified);
}

#[tokio::test]
async fn users_create_rejects_opaque_user_name_without_emails() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"the-username"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)["scimType"], "invalidValue");
}

#[tokio::test]
async fn users_patch_rejects_invalid_update_operation_with_scim_invalid_syntax() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);
    let user_id =
        create_scim_user(&router, &token, "patch-update@example.com", "Patch Update").await;

    let response = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"update","path":"userName","value":"ignored@example.com"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn users_delete_succeeds_without_content_type_header() {
    let (adapter, router) = router_with_adapter().expect("router");
    seed_plain_provider(adapter.as_ref(), "okta", "base-token").await;
    let token = encode_bearer_token("base-token", "okta", None);
    let user_id = create_scim_user(&router, &token, "delete@example.com", "Delete User").await;

    let response = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
