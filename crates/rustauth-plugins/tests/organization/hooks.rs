use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::{Method, StatusCode};
use rustauth_core::db::MemoryAdapter;
use rustauth_plugins::organization::{
    DefaultTeamSpec, MemberHookData, MemberRoleUpdateData, OrganizationHookData, OrganizationHooks,
    OrganizationOptions, OrganizationUpdateData, TeamHookData,
};
use serde_json::json;

#[tokio::test]
async fn invitation_email_hook_runs_in_background() -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let captured = sent.clone();
    let options = OrganizationOptions::builder()
        .send_invitation_email(Arc::new(move |email| {
            let captured = Arc::clone(&captured);
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                captured
                    .lock()
                    .map_err(|error| rustauth_core::error::RustAuthError::Api(error.to_string()))?
                    .push((
                        email.email.clone(),
                        email.role.clone(),
                        email.organization.id.clone(),
                    ));
                Ok(())
            })
        }))
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-hook@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Acme Hooks","slug":"acme-hooks"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"invited-hook@example.com","role":"member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);

    for _ in 0..200 {
        if sent.lock().map_err(|error| error.to_string())?.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let sent = sent.lock().map_err(|error| error.to_string())?;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "invited-hook@example.com");
    assert_eq!(sent[0].1, "member");
    assert_eq!(sent[0].2, org.body["id"]);
    Ok(())
}

#[tokio::test]
async fn before_create_organization_hook_can_mutate_name_and_slug(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OrganizationOptions::builder()
        .hooks(OrganizationHooks {
            before_create_organization: Some(Arc::new(|event| {
                Ok(OrganizationHookData {
                    name: format!("{} Hooked", event.organization.name),
                    slug: "hooked-create-org".to_owned(),
                })
            })),
            ..OrganizationHooks::default()
        })
        .teams(rustauth_plugins::organization::TeamOptions {
            enabled: true,
            create_default_team: true,
            ..Default::default()
        })
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-create-org-hook@example.com").await?;
    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Original","slug":"original-create-org"}),
        Some(&ada.cookie),
    )
    .await?;

    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["name"], "Original Hooked");
    assert_eq!(created.body["slug"], "hooked-create-org");
    assert_eq!(created.body["teams"].as_array().map(Vec::len), Some(1));
    assert_eq!(created.body["teams"][0]["name"], "Default");
    Ok(())
}

#[tokio::test]
async fn custom_create_default_team_controls_default_team_name(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OrganizationOptions::builder()
        .teams(rustauth_plugins::organization::TeamOptions {
            enabled: true,
            create_default_team: true,
            custom_create_default_team: Some(Arc::new(|organization| {
                Box::pin(async move {
                    Ok(DefaultTeamSpec {
                        name: format!("{} Launch", organization.name),
                    })
                })
            })),
            ..Default::default()
        })
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;
    let ada = super::sign_up(&auth, "Ada", "ada-custom-default-team@example.com").await?;

    let created = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Custom Default","slug":"custom-default-team"}),
        Some(&ada.cookie),
    )
    .await?;

    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["teams"].as_array().map(Vec::len), Some(1));
    assert_eq!(created.body["teams"][0]["name"], "Custom Default Launch");
    Ok(())
}

#[tokio::test]
async fn organization_update_and_delete_hooks_run_and_update_can_mutate(
) -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let options = OrganizationOptions::builder()
        .hooks(OrganizationHooks {
            before_update_organization: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-update:{}", event.organization.slug));
                    Ok(OrganizationUpdateData {
                        name: Some("Hooked Org".to_owned()),
                        slug: Some("hooked-org".to_owned()),
                        logo: event.data.logo.clone(),
                        metadata: event.data.metadata.clone(),
                    })
                }
            })),
            after_update_organization: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-update:{}", event.organization.slug));
                    Ok(())
                }
            })),
            before_delete_organization: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-delete:{}", event.organization.slug));
                    Ok(())
                }
            })),
            after_delete_organization: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-delete:{}", event.organization.slug));
                    Ok(())
                }
            })),
            ..OrganizationHooks::default()
        })
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;
    let ada = super::sign_up(&auth, "Ada", "ada-org-hooks@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Acme Hooks","slug":"acme-org-hooks"}),
        Some(&ada.cookie),
    )
    .await?;

    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update",
        json!({"organizationId":org.body["id"],"data":{"name":"Ignored","slug":"ignored"}}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["name"], "Hooked Org");
    assert_eq!(updated.body["slug"], "hooked-org");

    let deleted = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/delete",
        json!({"organizationId":org.body["id"]}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(deleted.status, StatusCode::OK);

    let calls = calls.lock().map_err(|error| error.to_string())?;
    assert_eq!(
        calls.as_slice(),
        [
            "before-update:acme-org-hooks",
            "after-update:hooked-org",
            "before-delete:hooked-org",
            "after-delete:hooked-org"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn member_hooks_run_and_before_hooks_can_mutate_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let options = OrganizationOptions::builder()
        .hooks(OrganizationHooks {
            before_add_member: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-add:{}", event.member.role));
                    Ok(MemberHookData {
                        role: "admin".to_owned(),
                        ..event.member.clone()
                    })
                }
            })),
            after_add_member: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-add:{}", event.member.role));
                    Ok(())
                }
            })),
            before_update_member_role: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-update-role:{}", event.new_role));
                    Ok(MemberRoleUpdateData {
                        role: "member".to_owned(),
                    })
                }
            })),
            after_update_member_role: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls.lock().map_err(lock_error)?.push(format!(
                        "after-update-role:{}->{}",
                        event.previous_role, event.member.role
                    ));
                    Ok(())
                }
            })),
            before_remove_member: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-remove:{}", event.member.role));
                    Ok(())
                }
            })),
            after_remove_member: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-remove:{}", event.member.role));
                    Ok(())
                }
            })),
            ..OrganizationHooks::default()
        })
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;
    let ada = super::sign_up(&auth, "Ada", "ada-member-hooks@example.com").await?;
    let ben = super::sign_up(&auth, "Ben", "ben-member-hooks@example.com").await?;
    super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Member Hooks","slug":"member-hooks"}),
        Some(&ada.cookie),
    )
    .await?;

    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId":ben.user_id,"role":"member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);
    assert_eq!(added.body["role"], "admin");
    let member_id = added.body["id"].as_str().ok_or("missing member id")?;

    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"memberId":member_id,"role":"admin"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["role"], "member");

    let removed = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/remove-member",
        json!({"memberIdOrEmail":member_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(removed.status, StatusCode::OK);

    let calls = calls.lock().map_err(|error| error.to_string())?;
    assert_eq!(
        calls.as_slice(),
        [
            "before-add:owner",
            "after-add:admin",
            "before-add:member",
            "after-add:admin",
            "before-update-role:admin",
            "after-update-role:admin->member",
            "before-remove:member",
            "after-remove:member"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn invitation_and_team_hooks_run_with_mutations() -> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let options = OrganizationOptions::builder()
        .teams(rustauth_plugins::organization::TeamOptions {
            enabled: true,
            ..rustauth_plugins::organization::TeamOptions::default()
        })
        .hooks(OrganizationHooks {
            before_create_invitation: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-invite:{}", event.invitation.email));
                    let mut invitation = event.invitation.clone();
                    invitation.email = "ben-invite-team-hooks@example.com".to_owned();
                    invitation.role = "admin".to_owned();
                    Ok(invitation)
                }
            })),
            after_create_invitation: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-invite:{}", event.invitation.role));
                    Ok(())
                }
            })),
            before_accept_invitation: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-accept:{}", event.invitation.email));
                    Ok(())
                }
            })),
            after_accept_invitation: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-accept:{}", event.member.role));
                    Ok(())
                }
            })),
            before_create_team: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("before-team:{}", event.team.name));
                    Ok(TeamHookData {
                        name: "Hooked Team".to_owned(),
                        ..event.team.clone()
                    })
                }
            })),
            after_create_team: Some(Arc::new({
                let calls = calls.clone();
                move |event| {
                    calls
                        .lock()
                        .map_err(lock_error)?
                        .push(format!("after-team:{}", event.team.name));
                    Ok(())
                }
            })),
            ..OrganizationHooks::default()
        })
        .build();
    let auth = super::test_router(Arc::new(MemoryAdapter::new()), options)?;
    let ada = super::sign_up(&auth, "Ada", "ada-invite-team-hooks@example.com").await?;
    let ben = super::sign_up(&auth, "Ben", "ben-invite-team-hooks@example.com").await?;
    super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Invite Team Hooks","slug":"invite-team-hooks"}),
        Some(&ada.cookie),
    )
    .await?;

    let team = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-team",
        json!({"name":"Ignored Team"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(team.status, StatusCode::OK);
    assert_eq!(team.body["name"], "Hooked Team");

    let invite = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"placeholder-hooks@example.com","role":"member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    assert_eq!(invite.body["email"], "ben-invite-team-hooks@example.com");
    assert_eq!(invite.body["role"], "admin");

    let accepted = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/accept-invitation",
        json!({"invitationId":invite.body["id"]}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(accepted.body["member"]["role"], "admin");

    let calls = calls.lock().map_err(|error| error.to_string())?;
    assert!(calls.contains(&"before-team:Ignored Team".to_owned()));
    assert!(calls.contains(&"after-team:Hooked Team".to_owned()));
    assert!(calls.contains(&"before-invite:placeholder-hooks@example.com".to_owned()));
    assert!(calls.contains(&"after-invite:admin".to_owned()));
    assert!(calls.contains(&"before-accept:ben-invite-team-hooks@example.com".to_owned()));
    assert!(calls.contains(&"after-accept:admin".to_owned()));
    Ok(())
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> rustauth_core::error::RustAuthError {
    rustauth_core::error::RustAuthError::Api(error.to_string())
}
