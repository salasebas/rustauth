//! User provisioning edge cases (upstream `scim.test.ts` POST /Users scenarios).

use super::*;

#[tokio::test]
async fn scim_post_user_links_account_to_existing_user_by_email() {
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

    let existing = DbUserStore::new(adapter.as_ref())
        .create_user(
            CreateUserInput::new("Existing User", "existing@email.com").email_verified(true),
        )
        .await
        .expect("existing user should create");
    let existing_id = existing.id.clone();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{
                "userName":"the-username",
                "emails":[{"value":"existing@email.com"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response);
    assert_eq!(body["id"], existing_id);
    assert_eq!(body["userName"], "existing@email.com");
    assert_eq!(body["displayName"], "Existing User");
    assert_eq!(body["externalId"], "the-username");
    assert_eq!(body["emails"][0]["value"], "existing@email.com");
    assert!(body["emails"][0]["primary"].as_bool().unwrap_or(false));

    let accounts = DbUserStore::new(adapter.as_ref())
        .list_accounts_for_user(&existing_id)
        .await
        .expect("accounts should list");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id, "okta");
}

#[tokio::test]
async fn scim_post_user_provisions_org_member_through_real_organization_hooks() {
    use openauth_plugins::organization::{MemberHookData, OrganizationHooks, OrganizationOptions};
    use std::sync::Arc;

    let organization_options = OrganizationOptions::builder()
        .hooks(OrganizationHooks {
            before_add_member: Some(Arc::new(|event| {
                Ok(MemberHookData {
                    role: "admin".to_owned(),
                    ..event.member.clone()
                })
            })),
            ..OrganizationHooks::default()
        })
        .build();
    let (adapter, router, _) = router_with_context_and_organization_options(
        crate::scim_options_for_manual_provider_tokens(),
        organization_options,
    )
    .expect("router should build");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("organization should create");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: Some("org_1".to_owned()),
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("base-token", "okta", Some("org_1"));

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"hooked-scim@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response);
    let user_id = body["id"].as_str().expect("user id").to_owned();
    let members = adapter.records("member").await;
    assert!(members.iter().any(|record| {
        record.get("organization_id") == Some(&DbValue::String("org_1".to_owned()))
            && record.get("user_id") == Some(&DbValue::String(user_id.clone()))
            && record.get("role") == Some(&DbValue::String("admin".to_owned()))
    }));
}

#[tokio::test]
async fn scim_delete_user_unlinks_provider_when_linked_by_email_across_providers() {
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

    let existing = DbUserStore::new(adapter.as_ref())
        .create_user(
            CreateUserInput::new("Shared User", "shared-delete@example.com").email_verified(true),
        )
        .await
        .expect("existing user should create");
    let existing_id = existing.id.clone();

    let okta_created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"shared-delete@example.com"}"#,
            Some(&okta_token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(okta_created.status(), StatusCode::CREATED);
    assert_eq!(json_body(okta_created)["id"], existing_id);

    let entra_created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"shared-delete@example.com"}"#,
            Some(&entra_token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(entra_created.status(), StatusCode::CREATED);
    assert_eq!(json_body(entra_created)["id"], existing_id);

    let accounts_before = DbUserStore::new(adapter.as_ref())
        .list_accounts_for_user(&existing_id)
        .await
        .expect("accounts should list");
    assert_eq!(accounts_before.len(), 2);

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{existing_id}"),
            &okta_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&existing_id)
        .await
        .expect("lookup should succeed")
        .expect("user should remain");
    assert_eq!(user.email, "shared-delete@example.com");

    let accounts_after = DbUserStore::new(adapter.as_ref())
        .list_accounts_for_user(&existing_id)
        .await
        .expect("accounts should list");
    assert_eq!(accounts_after.len(), 1);
    assert_eq!(accounts_after[0].provider_id, "entra");

    let okta_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{existing_id}"),
            &okta_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(okta_get.status(), StatusCode::NOT_FOUND);

    let entra_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{existing_id}"),
            &entra_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(entra_get.status(), StatusCode::OK);
}
