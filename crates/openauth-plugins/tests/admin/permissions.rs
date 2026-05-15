use http::{Method, StatusCode};
use serde_json::json;

use super::{create_user, json_body, request, Fixture};

#[tokio::test]
async fn has_permission_handles_edge_cases_and_legacy_alias(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { context, router } = super::fixture()?;
    let user = create_user(&context, "permission-user@example.com", "user").await?;

    let missing = router
        .handle_async(request(
            Method::POST,
            "/admin/has-permission",
            Some(json!({ "permissions": { "user": ["list"] } })),
            None,
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let empty = router
        .handle_async(request(
            Method::POST,
            "/admin/has-permission",
            Some(json!({ "userId": "", "permissions": { "user": ["list"] } })),
            None,
        )?)
        .await?;
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);

    let not_found = router
        .handle_async(request(
            Method::POST,
            "/admin/has-permission",
            Some(json!({ "userId": "missing", "permissions": { "user": ["list"] } })),
            None,
        )?)
        .await?;
    assert_eq!(not_found.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(not_found)?["message"], "user not found");

    let role_priority = router
        .handle_async(request(
            Method::POST,
            "/admin/has-permission",
            Some(
                json!({ "userId": user.id, "role": "admin", "permissions": { "user": ["create"] } }),
            ),
            None,
        )?)
        .await?;
    assert_eq!(json_body(role_priority)?["success"], true);

    let alias = router
        .handle_async(request(
            Method::POST,
            "/admin/has-permission",
            Some(json!({ "role": "admin", "permission": { "user": ["create"] } })),
            None,
        )?)
        .await?;
    assert_eq!(alias.status(), StatusCode::OK);
    assert_eq!(json_body(alias)?["success"], true);
    Ok(())
}
