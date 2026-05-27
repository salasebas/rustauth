//! [`ScimDeprovisionMode`] behavior.

use super::*;

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
