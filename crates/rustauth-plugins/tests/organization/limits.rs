use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::db::MemoryAdapter;
use rustauth_plugins::organization::{MembershipLimit, OrganizationLimit, OrganizationOptions};
use serde_json::json;

#[tokio::test]
async fn dynamic_membership_limit_callback_controls_add_member(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .membership_limit_dynamic(Arc::new(|context| {
                Box::pin(async move {
                    Ok(if context.organization.slug == "small-org" {
                        2
                    } else {
                        100
                    })
                })
            }))
            .build(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-limit@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Small Org","slug":"small-org"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let member_one = super::sign_up(&auth, "One", "member-one@example.com").await?;
    let member_two = super::sign_up(&auth, "Two", "member-two@example.com").await?;

    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": member_one.user_id, "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);

    let blocked = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": member_two.user_id, "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(
        blocked.body["code"],
        "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"
    );
    Ok(())
}

#[tokio::test]
async fn dynamic_organization_limit_callback_blocks_create(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .organization_limit_dynamic(Arc::new(|user| {
                let email = user.email.clone();
                Box::pin(async move { Ok(email.contains("blocked")) })
            }))
            .build(),
    )?;
    let blocked = super::sign_up(&auth, "Blocked", "blocked-limit@example.com").await?;
    let denied = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Denied Org","slug":"denied-org"}),
        Some(&blocked.cookie),
    )
    .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(
        denied.body["code"],
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"
    );

    let allowed = super::sign_up(&auth, "Allowed", "allowed-limit@example.com").await?;
    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Allowed Org","slug":"allowed-org"}),
        Some(&allowed.cookie),
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    Ok(())
}

#[test]
fn organization_limit_and_membership_limit_enums_are_constructible() {
    let _ = OrganizationLimit::Fixed(3);
    let _ = MembershipLimit::Fixed(10);
}
