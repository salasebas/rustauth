use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::organization::{OrganizationOptions, TeamOptions};
use serde_json::json;

#[tokio::test]
async fn active_organization_is_returned_from_get_session_and_refreshes_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-session@example.com").await?;

    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Session Org","slug":"session-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    assert!(org.set_cookie.is_some());

    let session = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/get-session",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(
        session.body["session"]["activeOrganizationId"],
        org.body["id"]
    );

    let cleared = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(cleared.status, StatusCode::OK);
    assert!(cleared.set_cookie.is_some());
    Ok(())
}

#[tokio::test]
async fn keep_current_active_organization_and_set_active_by_slug(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-keep-active@example.com").await?;

    let first = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"First Org","slug":"first-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);

    let second = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({
            "name":"Second Org",
            "slug":"second-org",
            "keepCurrentActiveOrganization": true
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);

    let session = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/get-session",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(
        session.body["session"]["activeOrganizationId"],
        first.body["id"]
    );

    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationSlug": "second-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);
    assert!(active.set_cookie.is_some());

    let session = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/get-session",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(
        session.body["session"]["activeOrganizationId"],
        second.body["id"]
    );
    Ok(())
}

#[tokio::test]
async fn unauthenticated_create_with_user_id_is_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    // A real user exists, but the attacker holds no session for them.
    let victim = super::sign_up(&auth, "Victim", "victim-ope9@example.com").await?;

    // An internet-facing request that forges the victim's `userId` without a
    // session must be rejected. `userId` is server-only (OPE-9).
    let forged = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Forged Org","slug":"forged-org","userId": victim.user_id}),
        None,
    )
    .await?;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);

    // The slug must still be free, proving no organization was provisioned for
    // the victim by the unauthenticated request.
    let legitimate = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Forged Org","slug":"forged-org"}),
        Some(&victim.cookie),
    )
    .await?;
    assert_eq!(legitimate.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn server_side_create_with_user_id_provisions_organization(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-server-create@example.com").await?;

    let created = super::server_request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({
            "name": "Delegated Org",
            "slug": "delegated-org",
            "userId": owner.user_id,
        }),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["name"], "Delegated Org");

    let full = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/get-full-organization?organizationSlug=delegated-org",
        json!({}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(full.status, StatusCode::OK);
    assert_eq!(full.body["slug"], "delegated-org");
    Ok(())
}

#[tokio::test]
async fn user_cannot_create_organization_when_disabled_but_server_can(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .allow_user_to_create_organization(false)
            .build(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-disabled-create@example.com").await?;

    let denied = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Denied Org","slug":"denied-create-org"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(
        denied.body["code"],
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"
    );

    let created = super::server_request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({
            "name": "Server Org",
            "slug": "server-create-org",
            "userId": owner.user_id
        }),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["slug"], "server-create-org");
    Ok(())
}

#[tokio::test]
async fn active_team_is_returned_from_get_session_when_teams_are_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OrganizationOptions::builder()
        .teams(TeamOptions {
            enabled: true,
            create_default_team: true,
            maximum_teams: None,
            maximum_members_per_team: None,
            allow_removing_all_teams: false,
            ..Default::default()
        })
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;
    let ada = super::sign_up(&auth, "Ada", "ada-active-team@example.com").await?;

    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Team Session Org","slug":"team-session-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let team = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-team",
        json!({"name":"Product"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team.status, StatusCode::OK);
    let team_id = team.body["id"].as_str().ok_or("missing team id")?;

    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active-team",
        json!({"teamId": team_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);
    assert!(active.set_cookie.is_some());

    let session = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/get-session",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["session"]["activeTeamId"], team_id);
    Ok(())
}
