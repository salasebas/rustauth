//! Bulk [`ScimBulkMode::Atomic`] behavior.

use super::*;

#[tokio::test]
async fn atomic_bulk_rejects_memory_adapter_without_native_transactions() {
    let (adapter, router, _context) = router_with_context(ScimOptions {
        bulk_mode: ScimBulkMode::Atomic,
        ..crate::scim_options_for_manual_provider_tokens()
    })
    .expect("router");
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

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[{"method":"GET","path":"/Users"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response);
    assert_eq!(body["scimType"], "invalidValue");
    assert!(body["detail"]
        .as_str()
        .expect("detail")
        .contains("native transaction support"));
}
