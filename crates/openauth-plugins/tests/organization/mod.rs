use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{
    DbAdapter, DbField, DbFieldType, DbRecord, DbValue, FindOne, MemoryAdapter, TableOptions, User,
    Where,
};
use openauth_core::options::OpenAuthOptions;
use openauth_core::test_utils::with_integration_test_defaults;
use openauth_plugins::organization::{
    has_permission, organization, organization_with, provision_organization_member, MemberHookData,
    OrganizationHooks, OrganizationOptions, OrganizationPermission, OrganizationRole,
    OrganizationSchemaOptions, ProvisionOrganizationMemberInput,
};
use serde_json::{json, Value};

mod additional_fields;
mod dynamic_access_control;
mod edge_cases;
mod hooks;
mod limits;
mod openapi;
mod query;
mod session;
mod teams;

#[test]
fn exposes_organization_plugin_surface() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        openauth_plugins::organization::UPSTREAM_PLUGIN_ID,
        "organization"
    );

    let plugin = organization();
    assert_eq!(plugin.id, "organization");
    assert!(plugin
        .endpoints
        .iter()
        .any(|endpoint| endpoint.path == "/organization/create"));
    assert!(plugin
        .error_codes
        .iter()
        .any(|code| code.code == "ORGANIZATION_NOT_FOUND"));
    Ok(())
}

#[test]
fn organization_schema_registers_core_tables_and_session_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![organization()],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter,
    )?;

    assert!(context.db_schema.table("organization").is_some());
    assert!(context.db_schema.table("member").is_some());
    assert!(context.db_schema.table("invitation").is_some());
    assert_eq!(
        context
            .db_schema
            .field_name("session", "active_organization_id")?,
        "active_organization_id"
    );
    Ok(())
}

#[test]
fn organization_schema_applies_custom_table_field_and_additional_field_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let schema = OrganizationSchemaOptions {
        organization: TableOptions::default()
            .with_name("tenant_orgs")
            .with_field_name("slug", "tenant_slug")
            .with_field(
                "billing_code",
                DbField::new("billing_code", DbFieldType::String)
                    .optional()
                    .hidden(),
            ),
        ..OrganizationSchemaOptions::default()
    };
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![organization_with(
                OrganizationOptions::builder().schema(schema).build(),
            )],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter,
    )?;

    assert_eq!(context.db_schema.table_name("organization")?, "tenant_orgs");
    assert_eq!(
        context.db_schema.field_name("organization", "slug")?,
        "tenant_slug"
    );
    let field = context.db_schema.field("organization", "billing_code")?;
    assert_eq!(field.name, "billing_code");
    assert!(!field.returned);
    Ok(())
}

#[test]
fn default_permissions_match_upstream_roles() {
    let options = OrganizationOptions::default();
    assert!(has_permission(
        OrganizationRole::Owner.as_str(),
        &options,
        OrganizationPermission::OrganizationDelete,
    ));
    assert!(has_permission(
        OrganizationRole::Admin.as_str(),
        &options,
        OrganizationPermission::MemberCreate,
    ));
    assert!(!has_permission(
        OrganizationRole::Member.as_str(),
        &options,
        OrganizationPermission::MemberCreate,
    ));
}

#[tokio::test]
async fn organization_routes_cover_create_members_and_invitations(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = test_router(adapter.clone(), OrganizationOptions::default())?;

    let ada = sign_up(&auth, "Ada", "ada@example.com").await?;
    let org = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Acme","slug":"acme"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    assert_eq!(org.body["slug"], "acme");
    assert_eq!(org.body["members"][0]["role"], "owner");

    let duplicate = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Acme 2","slug":"acme"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(duplicate.status, StatusCode::BAD_REQUEST);

    let ben = sign_up(&auth, "Ben", "ben@example.com").await?;
    let invite = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"email":"ben@example.com","role":"member"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(invite.status, StatusCode::OK);
    let invitation_id = invite.body["id"]
        .as_str()
        .ok_or("missing invitation id")?
        .to_owned();

    let accepted = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/accept-invitation",
        json!({"invitationId": invitation_id}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(accepted.body["member"]["role"], "member");

    let members = request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-members",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(members.status, StatusCode::OK);
    assert_eq!(members.body["members"].as_array().map(Vec::len), Some(2));

    let denied = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/delete",
        json!({"organizationId": org.body["id"]}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn non_creator_cannot_update_creator_member_or_assign_creator_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = test_router(adapter, OrganizationOptions::default())?;

    let owner = sign_up(&auth, "Owner", "owner-guard@example.com").await?;
    let admin = sign_up(&auth, "Admin", "admin-guard@example.com").await?;
    let member = sign_up(&auth, "Member", "member-guard@example.com").await?;
    let org = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Creator Guard","slug":"creator-guard"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let admin_added = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": admin.user_id, "role": "admin"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(admin_added.status, StatusCode::OK);
    let member_added = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": member.user_id, "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(member_added.status, StatusCode::OK);
    let owner_member_id = org.body["members"][0]["id"]
        .as_str()
        .ok_or("missing owner member id")?;
    let member_id = member_added.body["id"]
        .as_str()
        .ok_or("missing member id")?;
    let organization_id = org.body["id"].clone();

    let target_creator = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"organizationId": organization_id, "memberId": owner_member_id, "role": "member"}),
        Some(&admin.cookie),
    )
    .await?;
    assert_eq!(target_creator.status, StatusCode::FORBIDDEN);
    assert_eq!(
        target_creator.body["code"],
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"
    );

    let assign_creator = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"organizationId": organization_id, "memberId": member_id, "role": "owner"}),
        Some(&admin.cookie),
    )
    .await?;
    assert_eq!(assign_creator.status, StatusCode::FORBIDDEN);
    assert_eq!(
        assign_creator.body["code"],
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"
    );
    Ok(())
}

#[tokio::test]
async fn leave_organization_uses_body_organization_id_not_active_org(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = test_router(adapter, OrganizationOptions::default())?;

    let owner = sign_up(&auth, "Owner", "owner-leave@example.com").await?;
    let member = sign_up(&auth, "Member", "member-leave@example.com").await?;
    let first = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"First Leave","slug":"first-leave"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    let first_id = first.body["id"].clone();
    let second = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Second Leave","slug":"second-leave"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);
    let second_id = second.body["id"].clone();
    for organization_id in [&first_id, &second_id] {
        let added = request_json(
            &auth,
            Method::POST,
            "/api/auth/organization/add-member",
            json!({"organizationId": organization_id, "userId": member.user_id, "role": "member"}),
            Some(&owner.cookie),
        )
        .await?;
        assert_eq!(added.status, StatusCode::OK);
    }
    let active = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationId": second_id}),
        Some(&member.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);

    let left = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/leave",
        json!({"organizationId": first_id}),
        Some(&member.cookie),
    )
    .await?;
    assert_eq!(left.status, StatusCode::OK);

    let first_members = request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/list-members?organizationId={}",
            first_id.as_str().ok_or("first id")?
        ),
        json!({}),
        Some(&owner.cookie),
    )
    .await?;
    let second_members = request_json(
        &auth,
        Method::GET,
        &format!(
            "/api/auth/organization/list-members?organizationId={}",
            second_id.as_str().ok_or("second id")?
        ),
        json!({}),
        Some(&owner.cookie),
    )
    .await?;

    assert_eq!(first_members.status, StatusCode::OK);
    assert_eq!(second_members.status, StatusCode::OK);
    assert_eq!(first_members.body["total"], 1);
    assert_eq!(second_members.body["total"], 2);
    Ok(())
}

#[tokio::test]
async fn invite_member_normalizes_email_and_resend_extends_existing_invitation(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = test_router(adapter, OrganizationOptions::default())?;
    let owner = sign_up(&auth, "Owner", "owner-invite-resend@example.com").await?;
    let org = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Invite Resend","slug":"invite-resend"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].clone();

    let first = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": organization_id, "email": "  CASED-INVITE@example.COM  ", "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["email"], "cased-invite@example.com");
    let first_id = first.body["id"].clone();

    let duplicate = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": organization_id, "email": "cased-invite@example.com", "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(duplicate.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        duplicate.body["code"],
        "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"
    );

    let resent = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/invite-member",
        json!({"organizationId": organization_id, "email": "CASED-INVITE@example.com", "role": "member", "resend": true}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(resent.status, StatusCode::OK);
    assert_eq!(resent.body["id"], first_id);
    assert_eq!(resent.body["email"], "cased-invite@example.com");
    Ok(())
}

#[tokio::test]
async fn custom_creator_role_is_used_for_owner_guards() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = test_router(
        adapter,
        OrganizationOptions::builder()
            .creator_role("founder")
            .build(),
    )?;
    let founder = sign_up(&auth, "Founder", "founder-role@example.com").await?;
    let org = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Founder Org","slug":"founder-org"}),
        Some(&founder.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    assert_eq!(org.body["members"][0]["role"], "founder");
    let organization_id = org.body["id"].clone();
    let founder_member_id = org.body["members"][0]["id"]
        .as_str()
        .ok_or("missing founder member id")?;

    let demote = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"organizationId": organization_id, "memberId": founder_member_id, "role": "member"}),
        Some(&founder.cookie),
    )
    .await?;
    assert_eq!(demote.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        demote.body["code"],
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER"
    );

    let leave = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/leave",
        json!({"organizationId": org.body["id"]}),
        Some(&founder.cookie),
    )
    .await?;
    assert_eq!(leave.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        leave.body["code"],
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"
    );
    Ok(())
}

#[tokio::test]
async fn multi_role_owner_counts_for_last_owner_guards() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let auth = test_router(adapter, OrganizationOptions::default())?;
    let owner = sign_up(&auth, "Owner", "owner-multi-role@example.com").await?;
    let second = sign_up(&auth, "Second", "second-multi-role@example.com").await?;
    let org = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Multi Owner","slug":"multi-owner"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].clone();
    let owner_member_id = org.body["members"][0]["id"]
        .as_str()
        .ok_or("missing owner member id")?;

    let second_member = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": organization_id, "userId": second.user_id, "role": "admin, owner"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(second_member.status, StatusCode::OK);
    assert_eq!(second_member.body["role"], "admin,owner");

    let demoted_owner = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"organizationId": organization_id, "memberId": owner_member_id, "role": "member"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(demoted_owner.status, StatusCode::OK);
    assert_eq!(demoted_owner.body["role"], "member");

    let second_member_id = second_member.body["id"]
        .as_str()
        .ok_or("missing second member id")?;
    let denied = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-member-role",
        json!({"organizationId": organization_id, "memberId": second_member_id, "role": "admin"}),
        Some(&second.cookie),
    )
    .await?;
    assert_eq!(denied.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        denied.body["code"],
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER"
    );
    Ok(())
}

#[tokio::test]
async fn public_provision_organization_member_uses_member_semantics_and_hooks(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let hook_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let options = OrganizationOptions::builder()
        .membership_limit(2)
        .hooks(OrganizationHooks {
            before_add_member: Some(Arc::new({
                let hook_calls = hook_calls.clone();
                move |event| {
                    hook_calls
                        .lock()
                        .map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(error.to_string())
                        })?
                        .push(format!("before:{}", event.member.role));
                    Ok(MemberHookData {
                        role: "admin".to_owned(),
                        ..event.member.clone()
                    })
                }
            })),
            after_add_member: Some(Arc::new({
                let hook_calls = hook_calls.clone();
                move |event| {
                    hook_calls
                        .lock()
                        .map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(error.to_string())
                        })?
                        .push(format!("after:{}", event.member.role));
                    Ok(())
                }
            })),
            ..OrganizationHooks::default()
        })
        .build();
    let auth = test_router(adapter.clone(), options.clone())?;
    let owner = sign_up(&auth, "Owner", "owner-provision-helper@example.com").await?;
    let member = sign_up(&auth, "Member", "member-provision-helper@example.com").await?;
    let extra = sign_up(&auth, "Extra", "extra-provision-helper@example.com").await?;
    let org = request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Provision Helper","slug":"provision-helper"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing organization id")?;
    hook_calls
        .lock()
        .map_err(|error| error.to_string())?
        .clear();
    let member_record = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(member.user_id.clone()))),
        )
        .await?
        .ok_or("missing member user")?;
    let member_user = user_from_record(member_record)?;

    let provisioned = provision_organization_member(
        adapter.as_ref(),
        &options,
        ProvisionOrganizationMemberInput {
            organization_id,
            user: &member_user,
            role: "member",
        },
    )
    .await?;
    let provisioned = provisioned.ok_or("expected new member")?;
    assert_eq!(provisioned.organization_id, organization_id);
    assert_eq!(provisioned.user_id, member.user_id);
    assert_eq!(provisioned.role, "admin");

    let duplicate = provision_organization_member(
        adapter.as_ref(),
        &options,
        ProvisionOrganizationMemberInput {
            organization_id,
            user: &member_user,
            role: "member",
        },
    )
    .await?;
    assert!(duplicate.is_none());

    {
        let calls = hook_calls.lock().map_err(|error| error.to_string())?;
        assert_eq!(calls.as_slice(), ["before:member", "after:admin"]);
    }

    let extra_record = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(extra.user_id.clone()))),
        )
        .await?
        .ok_or("missing extra user")?;
    let extra_user = user_from_record(extra_record)?;
    let limit_result = provision_organization_member(
        adapter.as_ref(),
        &options,
        ProvisionOrganizationMemberInput {
            organization_id,
            user: &extra_user,
            role: "member",
        },
    )
    .await;
    let Err(limit_error) = limit_result else {
        return Err("expected membership limit".into());
    };
    assert!(limit_error
        .to_string()
        .contains("ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"));
    Ok(())
}

fn test_router(
    adapter: Arc<MemoryAdapter>,
    options: OrganizationOptions,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let adapter_dyn: Arc<dyn openauth_core::db::DbAdapter> = adapter;
    let context = create_auth_context_with_adapter(
        with_integration_test_defaults(OpenAuthOptions {
            plugins: vec![organization_with(options)],
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        }),
        adapter_dyn.clone(),
    )?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter_dyn),
    )?)
}

struct TestResponse {
    status: StatusCode,
    body: Value,
    set_cookie: Option<String>,
}

struct SignedUp {
    cookie: String,
    user_id: String,
}

fn user_from_record(record: DbRecord) -> Result<User, Box<dyn std::error::Error>> {
    let string = |field: &str| match record.get(field) {
        Some(DbValue::String(value)) => Ok(value.clone()),
        _ => Err(format!("missing string user field `{field}`")),
    };
    let bool_field = |field: &str| match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        _ => Err(format!("missing bool user field `{field}`")),
    };
    let timestamp = |field: &str| match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        _ => Err(format!("missing timestamp user field `{field}`")),
    };
    let optional_string = |field: &str| match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.clone())),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(format!("invalid optional string user field `{field}`")),
    };

    Ok(User {
        id: string("id")?,
        name: string("name")?,
        email: string("email")?,
        email_verified: bool_field("email_verified")?,
        image: optional_string("image")?,
        username: optional_string("username")?,
        display_username: optional_string("display_username")?,
        created_at: timestamp("created_at")?,
        updated_at: timestamp("updated_at")?,
    })
}

async fn sign_up(
    router: &AuthRouter,
    name: &str,
    email: &str,
) -> Result<SignedUp, Box<dyn std::error::Error>> {
    let response = request_json(
        router,
        Method::POST,
        "/api/auth/sign-up/email",
        json!({"name":name,"email":email,"password":"secret123"}),
        None,
    )
    .await?;
    assert_eq!(response.status, StatusCode::OK);
    let user_id = response.body["user"]["id"]
        .as_str()
        .ok_or("missing user id")?
        .to_owned();
    Ok(SignedUp {
        cookie: response.set_cookie.ok_or("missing session cookie")?,
        user_id,
    })
}

/// Drive a request through the trusted server-side entry point
/// ([`AuthRouter::handle_async_server`]) so server-only inputs such as explicit
/// `userId` are honored for trusted backend callers.
async fn server_request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    dispatch_json(router, method, path, body, cookie, true).await
}

async fn request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    dispatch_json(router, method, path, body, cookie, false).await
}

async fn dispatch_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    server_side: bool,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    let payload = if method == Method::GET && body == json!({}) {
        Vec::new()
    } else {
        serde_json::to_vec(&body)?
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !payload.is_empty() {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "http://localhost:3000");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let request = builder.body(payload)?;
    let response = if server_side {
        router.handle_async_server(request).await?
    } else {
        router.handle_async(request).await?
    };
    let status = response.status();
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("open-auth.session_token="))
        .and_then(|value| value.split(';').next().map(str::to_owned));
    let body = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body())?
    };
    Ok(TestResponse {
        status,
        body,
        set_cookie,
    })
}

#[test]
fn organization_default_roles_include_upstream_roles(
) -> Result<(), openauth_plugins::access::AccessError> {
    let roles = openauth_plugins::organization::access::default_roles()?;

    assert!(roles.contains_key("admin"));
    assert!(roles.contains_key("owner"));
    assert!(roles.contains_key("member"));
    Ok(())
}

#[test]
fn organization_owner_can_delete_organization() -> Result<(), openauth_plugins::access::AccessError>
{
    let owner = openauth_plugins::organization::access::owner_role()?;

    assert_eq!(
        owner.authorize_all(openauth_plugins::access::request([(
            "organization",
            ["delete"]
        )])),
        Ok(())
    );
    Ok(())
}

#[test]
fn organization_admin_can_update_but_not_delete_organization(
) -> Result<(), openauth_plugins::access::AccessError> {
    let admin = openauth_plugins::organization::access::admin_role()?;

    assert_eq!(
        admin.authorize_all(openauth_plugins::access::request([(
            "organization",
            ["update"]
        )])),
        Ok(())
    );
    assert_eq!(
        admin.authorize_all(openauth_plugins::access::request([(
            "organization",
            ["delete"]
        )])),
        Err(
            openauth_plugins::access::AccessError::UnauthorizedResource {
                resource: "organization".to_string()
            }
        )
    );
    Ok(())
}

#[test]
fn organization_member_can_read_access_control_only(
) -> Result<(), openauth_plugins::access::AccessError> {
    let member = openauth_plugins::organization::access::member_role()?;

    assert_eq!(
        member.authorize_all(openauth_plugins::access::request([("ac", ["read"])])),
        Ok(())
    );
    assert_eq!(
        member.authorize_all(openauth_plugins::access::request([("member", ["create"])])),
        Err(
            openauth_plugins::access::AccessError::UnauthorizedResource {
                resource: "member".to_string()
            }
        )
    );
    Ok(())
}
