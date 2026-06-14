use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::db::{DbAdapter, DbValue, MemoryAdapter, Update, Where};
use rustauth_plugins::organization::OrganizationOptions;
use serde_json::json;
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn prevent_creating_organization_empty_name_or_slug() -> Result<(), Box<dyn std::error::Error>>
{
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-empty-org@example.com").await?;

    for body in [
        json!({"name":"","slug":"valid-slug"}),
        json!({"name":"Valid","slug":""}),
        json!({"name":"  ","slug":"valid-slug-2"}),
        json!({"name":"Valid","slug":"  "}),
    ] {
        let response = super::request_json(
            &auth,
            Method::POST,
            "/api/auth/organization/create",
            body,
            Some(&ada.cookie),
        )
        .await?;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.body["code"], "INVALID_REQUEST_BODY");
    }
    Ok(())
}

#[tokio::test]
async fn prevent_updating_organization_to_empty_name_or_slug(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let ada = super::sign_up(&auth, "Ada", "ada-empty-update@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Update Guard","slug":"update-guard"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    for body in [
        json!({"data":{"name":""}}),
        json!({"data":{"slug":""}}),
        json!({"data":{"name":"  "}}),
        json!({"data":{"slug":"  "}}),
    ] {
        let response = super::request_json(
            &auth,
            Method::POST,
            "/api/auth/organization/update",
            body,
            Some(&ada.cookie),
        )
        .await?;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.body["code"], "INVALID_REQUEST_BODY");
    }
    Ok(())
}

#[tokio::test]
async fn reject_expired_invitation_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = super::test_router(adapter.clone(), OrganizationOptions::default())?;
    let owner = super::sign_up(&auth, "Owner", "owner-expired-invite@example.com").await?;
    let invitee = super::sign_up(&auth, "Invitee", "invitee-expired-invite@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Expired Invite","slug":"expired-invite"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"invitee-expired-invite@example.com","role":"member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    let invitation_id = invite.body["id"].as_str().ok_or("missing invitation id")?;

    adapter
        .update(
            Update::new("invitation")
                .where_clause(Where::new("id", DbValue::String(invitation_id.to_owned())))
                .data(
                    "expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::hours(1)),
                ),
        )
        .await?;

    let rejected = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/reject-invitation",
        json!({"invitationId": invitation_id}),
        Some(&invitee.cookie),
    )
    .await?;
    assert_eq!(rejected.status, StatusCode::OK);
    assert_eq!(rejected.body["invitation"]["status"], "rejected");
    Ok(())
}

#[tokio::test]
async fn list_user_invitations_omits_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-rejected-list@example.com").await?;
    let invitee = super::sign_up(&auth, "Invitee", "invitee-rejected-list@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Rejected List","slug":"rejected-list"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"invitee-rejected-list@example.com","role":"member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    let invitation_id = invite.body["id"].as_str().ok_or("missing invitation id")?;

    let rejected = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/reject-invitation",
        json!({"invitationId": invitation_id}),
        Some(&invitee.cookie),
    )
    .await?;
    assert_eq!(rejected.status, StatusCode::OK);

    let listed = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-user-invitations",
        json!({}),
        Some(&invitee.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body.as_array().map(Vec::len), Some(0));
    Ok(())
}

#[tokio::test]
async fn cancel_pending_invitations_on_re_invite_replaces_prior_pending(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::builder()
            .cancel_pending_invitations_on_re_invite(true)
            .build(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-reinvite-cancel@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Reinvite Cancel","slug":"reinvite-cancel"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].clone();

    let first = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": organization_id, "email":"reinvite-cancel@example.com","role":"member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["status"], "pending");
    let first_id = first.body["id"].clone();

    let second = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": organization_id, "email":"reinvite-cancel@example.com","role":"admin"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.body["status"], "pending");
    assert_ne!(second.body["id"], first_id);
    assert_eq!(second.body["role"], "admin");

    let listed = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-invitations",
        json!({}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    let pending: Vec<_> = listed
        .body
        .as_array()
        .into_iter()
        .flatten()
        .filter(|invite| invite["status"] == "pending")
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["id"], second.body["id"]);
    Ok(())
}

#[tokio::test]
async fn owner_can_remove_own_creator_role_when_not_sole_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let first_owner = super::sign_up(&auth, "First", "first-dual-owner@example.com").await?;
    let second_owner = super::sign_up(&auth, "Second", "second-dual-owner@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Dual Owner","slug":"dual-owner"}),
        Some(&first_owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].clone();
    let first_member_id = org.body["members"][0]["id"]
        .as_str()
        .ok_or("missing first member id")?;

    let second_added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": organization_id, "userId": second_owner.user_id, "role": "admin,owner"}),
        Some(&first_owner.cookie),
    )
    .await?;
    assert_eq!(second_added.status, StatusCode::OK);

    let demoted = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"organizationId": organization_id, "memberId": first_member_id, "role": []}),
        Some(&first_owner.cookie),
    )
    .await?;
    assert_eq!(demoted.status, StatusCode::OK);
    assert_eq!(demoted.body["role"], "");
    Ok(())
}

#[tokio::test]
async fn create_invitation_with_multiple_roles() -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let owner = super::sign_up(&auth, "Owner", "owner-multi-invite@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Multi Invite","slug":"multi-invite"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"multi-invite@example.com","role":["admin","member"]}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    assert_eq!(invite.body["role"], "admin,member");
    Ok(())
}

#[tokio::test]
async fn multi_role_owner_can_invite_with_owner_role() -> Result<(), Box<dyn std::error::Error>> {
    let auth = super::test_router(
        Arc::new(MemoryAdapter::new()),
        OrganizationOptions::default(),
    )?;
    let founder = super::sign_up(&auth, "Founder", "founder-multi-invite@example.com").await?;
    let co_owner = super::sign_up(&auth, "CoOwner", "coowner-multi-invite@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Multi Owner Invite","slug":"multi-owner-invite"}),
        Some(&founder.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].clone();

    let co_owner_member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": organization_id, "userId": co_owner.user_id, "role": "admin,owner"}),
        Some(&founder.cookie),
    )
    .await?;
    assert_eq!(co_owner_member.status, StatusCode::OK);

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": organization_id, "email":"new-owner-invite@example.com","role":"owner"}),
        Some(&co_owner.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    assert_eq!(invite.body["role"], "owner");
    Ok(())
}
