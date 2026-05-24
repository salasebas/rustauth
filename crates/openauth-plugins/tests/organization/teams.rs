use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::organization::{OrganizationOptions, TeamOptions};
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
