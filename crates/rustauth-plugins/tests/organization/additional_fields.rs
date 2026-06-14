use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::db::{DbField, DbFieldType, MemoryAdapter, TableOptions};
use rustauth_plugins::organization::{
    DynamicAccessControlOptions, OrganizationOptions, OrganizationSchemaOptions, TeamOptions,
};
use serde_json::json;

#[tokio::test]
async fn organization_additional_fields_persist_and_respect_returned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = OrganizationSchemaOptions {
        organization: TableOptions::default()
            .with_field(
                "billingCode",
                DbField::new("billing_code", DbFieldType::String).optional(),
            )
            .with_field(
                "internalCode",
                DbField::new("internal_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        ..OrganizationSchemaOptions::default()
    };
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder().schema(schema).build(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-org-fields@example.com").await?;

    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({
            "name": "Fields Org",
            "slug": "fields-org",
            "billingCode": "B-1",
            "internalCode": "hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["billingCode"], "B-1");
    assert!(created.body.get("internalCode").is_none());

    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update",
        json!({
            "data": {
                "billingCode": "B-2",
                "internalCode": "still-hidden"
            }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["billingCode"], "B-2");
    assert!(updated.body.get("internalCode").is_none());

    let listed = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body[0]["billingCode"], "B-2");
    assert!(listed.body[0].get("internalCode").is_none());
    Ok(())
}

#[tokio::test]
async fn organization_role_additional_fields_persist_and_respect_returned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = OrganizationSchemaOptions {
        organization_role: TableOptions::default()
            .with_field(
                "scopeLabel",
                DbField::new("scope_label", DbFieldType::String).optional(),
            )
            .with_field(
                "internalRoleCode",
                DbField::new("internal_role_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        ..OrganizationSchemaOptions::default()
    };
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .dynamic_access_control(DynamicAccessControlOptions {
                enabled: true,
                maximum_roles_per_organization: None,
            })
            .schema(schema)
            .build(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-role-fields@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Role Fields Org","slug":"role-fields-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "role": "auditor",
            "permission": { "organization": ["read"], "ac": ["read"] },
            "scopeLabel": "audit",
            "internalRoleCode": "hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["scopeLabel"], "audit");
    assert!(created.body.get("internalRoleCode").is_none());

    let role_id = created.body["id"].as_str().ok_or("missing role id")?;
    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-role",
        json!({
            "roleId": role_id,
            "scopeLabel": "audit-updated",
            "internalRoleCode": "still-hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["scopeLabel"], "audit-updated");
    assert!(updated.body.get("internalRoleCode").is_none());

    let listed = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-roles",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body[0]["scopeLabel"], "audit-updated");
    assert!(listed.body[0].get("internalRoleCode").is_none());
    Ok(())
}

#[tokio::test]
async fn member_additional_fields_persist_and_respect_returned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = OrganizationSchemaOptions {
        member: TableOptions::default()
            .with_field(
                "department",
                DbField::new("department", DbFieldType::String).optional(),
            )
            .with_field(
                "internalMemberCode",
                DbField::new("internal_member_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        ..OrganizationSchemaOptions::default()
    };
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder().schema(schema).build(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-member-fields@example.com").await?;
    let ben = super::sign_up(&auth, "Ben", "ben-member-fields@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Member Fields Org","slug":"member-fields-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({
            "userId": ben.user_id,
            "role": "member",
            "department": "support",
            "internalMemberCode": "hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);
    assert_eq!(added.body["department"], "support");
    assert!(added.body.get("internalMemberCode").is_none());
    let member_id = added.body["id"].as_str().ok_or("missing member id")?;

    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({
            "memberId": member_id,
            "role": "admin",
            "department": "ops",
            "internalMemberCode": "still-hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["department"], "ops");
    assert!(updated.body.get("internalMemberCode").is_none());

    let members = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-members",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(members.status, StatusCode::OK);
    let ben_member = members.body["members"]
        .as_array()
        .and_then(|members| {
            members
                .iter()
                .find(|member| member["id"] == updated.body["id"])
        })
        .ok_or("missing updated member")?;
    assert_eq!(ben_member["department"], "ops");
    assert!(ben_member.get("internalMemberCode").is_none());

    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationId": org.body["id"]}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);
    let active_member = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/get-active-member",
        json!({}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(active_member.status, StatusCode::OK);
    assert_eq!(active_member.body["department"], "ops");
    assert!(active_member.body.get("internalMemberCode").is_none());
    Ok(())
}

#[tokio::test]
async fn team_additional_fields_persist_and_respect_returned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = OrganizationSchemaOptions {
        team: TableOptions::default()
            .with_field(
                "region",
                DbField::new("region", DbFieldType::String).optional(),
            )
            .with_field(
                "internalTeamCode",
                DbField::new("internal_team_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        team_member: TableOptions::default()
            .with_field(
                "seatLabel",
                DbField::new("seat_label", DbFieldType::String).optional(),
            )
            .with_field(
                "internalSeatCode",
                DbField::new("internal_seat_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        ..OrganizationSchemaOptions::default()
    };
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .teams(TeamOptions {
                enabled: true,
                create_default_team: false,
                maximum_teams: None,
                maximum_members_per_team: None,
                allow_removing_all_teams: true,
                ..Default::default()
            })
            .schema(schema)
            .build(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-team-fields@example.com").await?;
    let ben = super::sign_up(&auth, "Ben", "ben-team-fields@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Team Fields Org","slug":"team-fields-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let add_member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": ben.user_id, "role": "member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(add_member.status, StatusCode::OK);

    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-team",
        json!({
            "name": "Platform",
            "region": "latam",
            "internalTeamCode": "hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["region"], "latam");
    assert!(created.body.get("internalTeamCode").is_none());
    let team_id = created.body["id"].as_str().ok_or("missing team id")?;

    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-team",
        json!({
            "teamId": team_id,
            "name": "Platform Ops",
            "region": "global",
            "internalTeamCode": "still-hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["region"], "global");
    assert!(updated.body.get("internalTeamCode").is_none());

    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active-team",
        json!({"teamId": team_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);
    assert_eq!(active.body["region"], "global");

    let add_team_member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-team-member",
        json!({
            "teamId": team_id,
            "userId": ben.user_id,
            "seatLabel": "support-seat",
            "internalSeatCode": "hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(add_team_member.status, StatusCode::OK);
    assert_eq!(add_team_member.body["seatLabel"], "support-seat");
    assert!(add_team_member.body.get("internalSeatCode").is_none());

    let teams = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-teams",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(teams.status, StatusCode::OK);
    assert_eq!(teams.body[0]["region"], "global");
    assert!(teams.body[0].get("internalTeamCode").is_none());

    let team_members = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/list-team-members?teamId={team_id}"),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team_members.status, StatusCode::OK);
    let ben_team_member = team_members
        .body
        .as_array()
        .and_then(|members| {
            members
                .iter()
                .find(|member| member["userId"] == ben.user_id)
        })
        .ok_or("missing team member")?;
    assert_eq!(ben_team_member["seatLabel"], "support-seat");
    assert!(ben_team_member.get("internalSeatCode").is_none());
    Ok(())
}

#[tokio::test]
async fn invitation_additional_fields_persist_and_respect_returned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = OrganizationSchemaOptions {
        invitation: TableOptions::default()
            .with_field(
                "inviteNote",
                DbField::new("invite_note", DbFieldType::String).optional(),
            )
            .with_field(
                "internalInviteCode",
                DbField::new("internal_invite_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        ..OrganizationSchemaOptions::default()
    };
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder().schema(schema).build(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-invite-fields@example.com").await?;
    let ben = super::sign_up(&auth, "Ben", "ben-invite-fields@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Invite Fields Org","slug":"invite-fields-org"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({
            "email": "ben-invite-fields@example.com",
            "role": "member",
            "inviteNote": "welcome",
            "internalInviteCode": "hidden"
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    assert_eq!(invite.body["inviteNote"], "welcome");
    assert!(invite.body.get("internalInviteCode").is_none());
    let invitation_id = invite.body["id"].as_str().ok_or("missing invitation id")?;

    let fetched = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-invitation?invitationId={invitation_id}"),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body["inviteNote"], "welcome");
    assert!(fetched.body.get("internalInviteCode").is_none());

    let org_invitations = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-invitations",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org_invitations.status, StatusCode::OK);
    assert_eq!(org_invitations.body[0]["inviteNote"], "welcome");
    assert!(org_invitations.body[0].get("internalInviteCode").is_none());

    let user_invitations = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-user-invitations",
        json!({}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(user_invitations.status, StatusCode::OK);
    assert_eq!(user_invitations.body[0]["inviteNote"], "welcome");
    assert!(user_invitations.body[0].get("internalInviteCode").is_none());
    Ok(())
}
