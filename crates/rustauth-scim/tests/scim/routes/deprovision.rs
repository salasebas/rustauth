//! [`ScimDeprovisionMode`] behavior.

use super::*;
use rustauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};

#[tokio::test]
async fn default_deprovision_keeps_user_with_pre_existing_credential_account() {
    let (adapter, router, _context) =
        router_with_context(crate::scim_options_for_manual_provider_tokens()).expect("router");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "okta-secret".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("okta-secret", "okta", None);

    let existing = DbUserStore::new(adapter.as_ref())
        .create_user(
            CreateUserInput::new("Password User", "credential-keep@example.com")
                .email_verified(true),
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
            r#"{"userName":"credential-keep@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(linked.status(), StatusCode::CREATED);
    assert_eq!(json_body(linked)["id"], existing.id);

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{}", existing.id),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&existing.id)
        .await
        .expect("lookup should succeed")
        .expect("user should remain");
    assert_eq!(user.email, "credential-keep@example.com");

    let accounts = DbUserStore::new(adapter.as_ref())
        .list_accounts_for_user(&existing.id)
        .await
        .expect("accounts should list");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id, "credential");
}

#[tokio::test]
async fn delete_user_mode_removes_user_when_only_scim_provider_account_exists() {
    let (adapter, router, _context) = router_with_context(ScimOptions {
        deprovision_mode: ScimDeprovisionMode::DeleteUser,
        ..crate::scim_options_for_manual_provider_tokens()
    })
    .expect("router");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "okta-secret".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("okta-secret", "okta", None);

    let user_id =
        create_scim_user(&router, &token, "scim-only-delete@example.com", "SCIM Only").await;

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let user_gone = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&user_id)
        .await
        .expect("lookup should succeed");
    assert!(user_gone.is_none());
}

#[tokio::test]
async fn unlink_deprovision_keeps_user_when_another_provider_account_exists() {
    let (adapter, router, _context) = router_with_context(ScimOptions {
        deprovision_mode: ScimDeprovisionMode::UnlinkAccount,
        ..crate::scim_options_for_manual_provider_tokens()
    })
    .expect("router");
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
        &okta_token,
        "unlink-keep@example.com",
        "Unlink Keep",
    )
    .await;
    let linked = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"unlink-keep@example.com"}"#,
            Some(&entra_token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(linked.status(), StatusCode::CREATED);
    assert_eq!(json_body(linked)["id"], user_id);

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &okta_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let user = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&user_id)
        .await
        .expect("lookup should succeed")
        .expect("user should remain");
    assert_eq!(user.email, "unlink-keep@example.com");

    let accounts = DbUserStore::new(adapter.as_ref())
        .list_accounts_for_user(&user_id)
        .await
        .expect("accounts should list");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id, "entra");

    let okta_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &okta_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(okta_get.status(), StatusCode::NOT_FOUND);

    let entra_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &entra_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(entra_get.status(), StatusCode::OK);
}

#[tokio::test]
async fn unlink_deprovision_preserves_org_membership_when_another_org_scoped_provider_remains() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        deprovision_mode: ScimDeprovisionMode::UnlinkAccount,
        ..crate::scim_options_for_manual_provider_tokens()
    })
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

    let token_a = generate_scim_token(&router, &admin_cookie, "provider-a", Some("org_1")).await;
    let token_b = generate_scim_token(&router, &admin_cookie, "provider-b", Some("org_1")).await;

    let user_id = create_scim_user(
        &router,
        &token_a,
        "dual-provider@example.com",
        "Dual Provider",
    )
    .await;

    let linked = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"dual-provider@example.com"}"#,
            Some(&token_b),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(linked.status(), StatusCode::CREATED);
    assert_eq!(json_body(linked)["id"], user_id);

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &token_a,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String("org_1".to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.clone()))),
        )
        .await
        .expect("member lookup should succeed");
    assert!(member.is_some());

    let provider_a_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token_a,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(provider_a_get.status(), StatusCode::NOT_FOUND);

    let provider_b_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token_b,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(provider_b_get.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_user_deprovision_preserves_org_membership_when_another_org_scoped_provider_remains()
{
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        deprovision_mode: ScimDeprovisionMode::DeleteUser,
        ..crate::scim_options_for_manual_provider_tokens()
    })
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

    let token_a = generate_scim_token(&router, &admin_cookie, "provider-a", Some("org_1")).await;
    let token_b = generate_scim_token(&router, &admin_cookie, "provider-b", Some("org_1")).await;

    let user_id = create_scim_user(
        &router,
        &token_a,
        "delete-dual-provider@example.com",
        "Delete Dual Provider",
    )
    .await;

    let linked = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"delete-dual-provider@example.com"}"#,
            Some(&token_b),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(linked.status(), StatusCode::CREATED);
    assert_eq!(json_body(linked)["id"], user_id);

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &token_a,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String("org_1".to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.clone()))),
        )
        .await
        .expect("member lookup should succeed");
    assert!(member.is_some());

    let provider_b_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token_b,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(provider_b_get.status(), StatusCode::OK);
}

#[tokio::test]
async fn unlink_deprovision_removes_org_membership_when_last_org_scoped_provider_is_unlinked() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        deprovision_mode: ScimDeprovisionMode::UnlinkAccount,
        ..crate::scim_options_for_manual_provider_tokens()
    })
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

    let token = generate_scim_token(&router, &admin_cookie, "provider-a", Some("org_1")).await;
    let user_id = create_scim_user(
        &router,
        &token,
        "single-provider@example.com",
        "Single Provider",
    )
    .await;

    let deleted = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

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
    assert!(member.is_none());
}
