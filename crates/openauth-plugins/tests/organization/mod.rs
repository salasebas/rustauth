use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbField, DbFieldType, MemoryAdapter, TableOptions};
use openauth_core::options::{EmailPasswordOptions, OpenAuthOptions};
use openauth_plugins::organization::{
    has_permission, organization, organization_with_options, OrganizationOptions,
    OrganizationPermission, OrganizationRole, OrganizationSchemaOptions,
};
use serde_json::{json, Value};

mod additional_fields;
mod dynamic_access_control;
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
            plugins: vec![organization_with_options(
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

fn test_router(
    adapter: Arc<MemoryAdapter>,
    options: OrganizationOptions,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let adapter_dyn: Arc<dyn openauth_core::db::DbAdapter> = adapter;
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![organization_with_options(options)],
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new().enabled(true),
            development: true,
            ..OpenAuthOptions::default()
        },
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

async fn request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
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
    let response = router.handle_async(builder.body(payload)?).await?;
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
