use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::db::MemoryAdapter;
use rustauth_plugins::organization::{OrganizationOptions, TeamOptions};
use serde_json::json;

#[tokio::test]
async fn team_routes_cover_default_team_members_and_active_team(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = OrganizationOptions::builder()
        .teams(TeamOptions {
            enabled: true,
            create_default_team: true,
            maximum_teams: Some(3),
            maximum_members_per_team: Some(3),
            allow_removing_all_teams: false,
            ..Default::default()
        })
        .build();
    let auth = super::test_router(adapter, options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-team@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Acme Teams","slug":"acme-teams"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let full = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/get-full-organization",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(full.status, StatusCode::OK);
    assert_eq!(full.body["teams"].as_array().map(Vec::len), Some(1));

    let team = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-team",
        json!({"name":"Engineering"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team.status, StatusCode::OK);
    let team_id = team.body["id"].as_str().ok_or("missing team id")?;

    let ben = super::sign_up(&auth, "Ben", "ben-team@example.com").await?;
    let member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": ben.user_id, "role": "member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(member.status, StatusCode::OK);

    let team_member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-team-member",
        json!({"teamId": team_id, "userId": ben.user_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team_member.status, StatusCode::OK);

    let listed = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/list-team-members?teamId={team_id}"),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body.as_array().map(Vec::len), Some(2));

    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active-team",
        json!({"teamId": team_id}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn accepting_invitation_to_full_team_does_not_create_partial_membership(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = OrganizationOptions::builder()
        .teams(TeamOptions {
            enabled: true,
            create_default_team: false,
            maximum_teams: None,
            maximum_members_per_team: Some(2),
            allow_removing_all_teams: true,
            ..Default::default()
        })
        .build();
    let auth = super::test_router(adapter, options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-team-limit@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Team Limit","slug":"team-limit"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let team = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-team",
        json!({"name":"Engineering"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team.status, StatusCode::OK);
    let team_id = team.body["id"].as_str().ok_or("missing team id")?;

    let ben = super::sign_up(&auth, "Ben", "ben-team-limit@example.com").await?;
    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"ben-team-limit@example.com","role":"member","teamId":team_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    let invitation_id = invite.body["id"]
        .as_str()
        .ok_or("missing invitation id")?
        .to_owned();

    let carol = super::sign_up(&auth, "Carol", "carol-team-limit@example.com").await?;
    let member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": carol.user_id, "role": "member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(member.status, StatusCode::OK);
    let team_member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-team-member",
        json!({"teamId": team_id, "userId": carol.user_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team_member.status, StatusCode::OK);

    let accepted = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/accept-invitation",
        json!({"invitationId": invitation_id}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(accepted.status, StatusCode::FORBIDDEN);
    assert_eq!(accepted.body["code"], "TEAM_MEMBER_LIMIT_REACHED");

    let members = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-members",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(members.status, StatusCode::OK);
    assert_eq!(members.body["members"].as_array().map(Vec::len), Some(2));

    Ok(())
}

#[tokio::test]
async fn create_team_respects_explicit_organization_id_over_active_org(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = OrganizationOptions::builder()
        .teams(TeamOptions {
            enabled: true,
            create_default_team: false,
            allow_removing_all_teams: true,
            ..TeamOptions::default()
        })
        .build();
    let auth = super::test_router(adapter, options)?;
    let owner = super::sign_up(&auth, "Owner", "owner-team-explicit@example.com").await?;
    let first = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"First Team Org","slug":"first-team-org"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    let first_id = first.body["id"].as_str().ok_or("missing first org id")?;
    let second = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Second Team Org","slug":"second-team-org"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);
    let second_id = second.body["id"].as_str().ok_or("missing second org id")?;

    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-team",
        json!({"organizationId": first_id, "name":"Explicit First"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["organizationId"], first_id);

    let first_full = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-full-organization?organizationId={first_id}"),
        json!({}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(first_full.status, StatusCode::OK);
    assert_eq!(first_full.body["teams"].as_array().map(Vec::len), Some(1));
    let second_full = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-full-organization?organizationId={second_id}"),
        json!({}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(second_full.status, StatusCode::OK);
    assert_eq!(
        second_full
            .body
            .get("teams")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len),
        0
    );
    Ok(())
}

#[tokio::test]
async fn remove_team_blocks_last_team_unless_option_allows_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked_auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .teams(TeamOptions {
                enabled: true,
                create_default_team: true,
                allow_removing_all_teams: false,
                ..TeamOptions::default()
            })
            .build(),
    )?;
    let owner = super::sign_up(
        &blocked_auth,
        "Owner",
        "owner-last-team-blocked@example.com",
    )
    .await?;
    let org = super::request_json(
        &blocked_auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Last Team Blocked","slug":"last-team-blocked"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let team_id = org.body["teams"][0]["id"]
        .as_str()
        .ok_or("missing default team id")?;
    let denied = super::request_json(
        &blocked_auth,
        Method::POST,
        "/api/auth/organization/remove-team",
        json!({"teamId": team_id}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(denied.status, StatusCode::BAD_REQUEST);
    assert_eq!(denied.body["code"], "UNABLE_TO_REMOVE_LAST_TEAM");

    let allowed_auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .teams(TeamOptions {
                enabled: true,
                create_default_team: true,
                allow_removing_all_teams: true,
                ..TeamOptions::default()
            })
            .build(),
    )?;
    let owner = super::sign_up(
        &allowed_auth,
        "Owner",
        "owner-last-team-allowed@example.com",
    )
    .await?;
    let org = super::request_json(
        &allowed_auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Last Team Allowed","slug":"last-team-allowed"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let team_id = org.body["teams"][0]["id"]
        .as_str()
        .ok_or("missing default team id")?;
    let removed = super::request_json(
        &allowed_auth,
        Method::POST,
        "/api/auth/organization/remove-team",
        json!({"teamId": team_id}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(removed.status, StatusCode::OK);
    assert_eq!(removed.body["team"]["id"], team_id);
    Ok(())
}
