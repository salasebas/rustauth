use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::organization::{OrganizationOptions, TeamOptions};
use serde_json::json;

#[tokio::test]
async fn get_full_organization_accepts_id_slug_and_returns_null_without_active(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-full-query@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Full Query Org","slug":"full-query-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"].as_str().ok_or("missing organization id")?;

    let cleared = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(cleared.status, StatusCode::OK);

    let inactive = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/get-full-organization",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(inactive.status, StatusCode::OK);
    assert!(inactive.body.is_null());

    let by_id = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-full-organization?organizationId={org_id}"),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(by_id.status, StatusCode::OK);
    assert_eq!(by_id.body["id"], org_id);

    let by_slug = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/get-full-organization?organizationSlug=full-query-org",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(by_slug.status, StatusCode::OK);
    assert_eq!(by_slug.body["id"], org_id);
    Ok(())
}

#[tokio::test]
async fn get_full_organization_prioritizes_slug_over_id_when_both_provided(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-slug-priority@example.com").await?;
    let first = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"First Priority","slug":"first-priority"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    let first_id = first.body["id"].as_str().ok_or("missing first id")?;
    let second = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Second Priority","slug":"second-priority"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);

    let resolved = super::request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/get-full-organization?organizationId={first_id}&organizationSlug=second-priority"
        ),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(resolved.status, StatusCode::OK);
    assert_eq!(resolved.body["name"], "Second Priority");
    assert_eq!(resolved.body["slug"], "second-priority");
    Ok(())
}

#[tokio::test]
async fn list_organizations_returns_all_member_organizations(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-list-orgs@example.com").await?;
    for (name, slug) in [("Org One", "org-one"), ("Org Two", "org-two")] {
        let created = super::request_json(
            &auth,
            Method::POST,
            "/api/auth/organization/create",
            json!({"name": name, "slug": slug}),
            Some(&ada.cookie),
        )
        .await?;
        assert_eq!(created.status, StatusCode::OK);
    }

    let listed = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    let organizations = listed
        .body
        .as_array()
        .ok_or("expected organization array")?;
    assert_eq!(organizations.len(), 2);
    let slugs = organizations
        .iter()
        .filter_map(|org| org["slug"].as_str())
        .collect::<Vec<_>>();
    assert!(slugs.contains(&"org-one"));
    assert!(slugs.contains(&"org-two"));
    Ok(())
}

#[tokio::test]
async fn check_slug_reports_available_and_taken_slugs() -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let available = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/check-slug",
        json!({"slug":"fresh-slug"}),
        None,
    )
    .await?;
    assert_eq!(available.status, StatusCode::OK);
    assert_eq!(available.body["status"], true);

    let ada = super::sign_up(&auth, "Ada", "ada-check-slug@example.com").await?;
    let _created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Taken Slug Org","slug":"taken-slug"}),
        Some(&ada.cookie),
    )
    .await?;

    let taken = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/check-slug",
        json!({"slug":"taken-slug"}),
        None,
    )
    .await?;
    assert_eq!(taken.status, StatusCode::BAD_REQUEST);
    assert_eq!(taken.body["code"], "ORGANIZATION_SLUG_ALREADY_TAKEN");
    Ok(())
}

#[tokio::test]
async fn get_full_organization_rejects_non_member() -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-full-forbidden@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Forbidden Org","slug":"forbidden-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"].as_str().ok_or("missing organization id")?;
    let eve = super::sign_up(&auth, "Eve", "eve-full-forbidden@example.com").await?;

    let response = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-full-organization?organizationId={org_id}"),
        json!({}),
        Some(&eve.cookie),
    )
    .await?;

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(
        response.body["code"],
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"
    );
    Ok(())
}

#[tokio::test]
async fn get_full_organization_returns_all_members_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-full-limit-default@example.com").await?;
    let member = super::sign_up(&auth, "Member", "member-full-limit-default@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Full Limit Default","slug":"full-limit-default"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"].as_str().ok_or("missing organization id")?;
    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": org_id, "userId": member.user_id, "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);

    let response = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-full-organization?organizationId={org_id}"),
        json!({}),
        Some(&owner.cookie),
    )
    .await?;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["members"].as_array().map(Vec::len), Some(2));
    Ok(())
}

#[tokio::test]
async fn get_full_organization_members_limit_truncates_members_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .teams(TeamOptions {
                enabled: true,
                ..TeamOptions::default()
            })
            .build(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-full-limit@example.com").await?;
    let member = super::sign_up(&auth, "Member", "member-full-limit@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Full Limit Org","slug":"full-limit-org"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"].as_str().ok_or("missing organization id")?;
    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": org_id, "userId": member.user_id, "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);
    let invited = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": org_id, "email": "invitee-full-limit@example.com", "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(invited.status, StatusCode::OK);

    let response = super::request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/get-full-organization?organizationId={org_id}&membersLimit=1"
        ),
        json!({}),
        Some(&owner.cookie),
    )
    .await?;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        response.body["invitations"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(response.body["teams"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn list_members_supports_id_slug_pagination_filter_sort_and_total(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-members-query@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Members Query Org","slug":"members-query-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"]
        .as_str()
        .ok_or("missing organization id")?
        .to_owned();
    let ben = super::sign_up(&auth, "Ben", "ben-members-query@example.com").await?;
    let cara = super::sign_up(&auth, "Cara", "cara-members-query@example.com").await?;

    for user_id in [&ben.user_id, &cara.user_id] {
        let response = super::request_json(
            &auth,
            Method::POST,
            "/api/auth/organization/add-member",
            json!({"organizationId": org_id, "userId": user_id, "role": "member"}),
            Some(&ada.cookie),
        )
        .await?;
        assert_eq!(response.status, StatusCode::OK);
    }

    let paged = super::request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/list-members?organizationId={org_id}&limit=1&offset=1&sortBy=created_at&sortDirection=asc"
        ),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(paged.status, StatusCode::OK);
    assert_eq!(paged.body["total"], 3);
    assert_eq!(paged.body["members"].as_array().map(Vec::len), Some(1));

    let filtered = super::request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/list-members?organizationSlug=members-query-org&filterField=user_id&filterValue={}",
            ben.user_id
        ),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(filtered.status, StatusCode::OK);
    assert_eq!(filtered.body["total"], 1);
    assert_eq!(filtered.body["members"][0]["userId"], ben.user_id);
    Ok(())
}

#[tokio::test]
async fn list_members_rejects_non_member() -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-members-forbidden@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Members Forbidden Org","slug":"members-forbidden-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"].as_str().ok_or("missing organization id")?;
    let eve = super::sign_up(&auth, "Eve", "eve-members-forbidden@example.com").await?;

    let response = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/list-members?organizationId={org_id}"),
        json!({}),
        Some(&eve.cookie),
    )
    .await?;

    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(
        response.body["code"],
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"
    );
    Ok(())
}

#[tokio::test]
async fn get_active_member_role_supports_user_id_and_organization_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-role-query@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Role Query Org","slug":"role-query-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let org_id = org.body["id"].as_str().ok_or("missing organization id")?;
    let ben = super::sign_up(&auth, "Ben", "ben-role-query@example.com").await?;
    let member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": org_id, "userId": ben.user_id, "role": "member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(member.status, StatusCode::OK);

    let role = super::request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/get-active-member-role?organizationId={org_id}&userId={}",
            ben.user_id
        ),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;

    assert_eq!(role.status, StatusCode::OK);
    assert_eq!(role.body["role"], "member");
    Ok(())
}
