use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{ApiResponse, AuthRouter};
use openauth_core::context::{create_auth_context_with_adapter, AuthContext};
use openauth_core::cookies::sign_cookie_value;
use openauth_core::db::{Create, DbValue, MemoryAdapter};
use openauth_core::options::OpenAuthOptions;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_plugins::admin::{admin, AdminOptions};
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

mod openapi;
mod parity;
mod permissions;

#[test]
fn exposes_admin_plugin_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = admin(AdminOptions::default());
    assert_eq!(plugin.id, "admin");
    assert_eq!(plugin.endpoints.len(), 15);
    assert!(plugin
        .error_codes
        .iter()
        .any(|code| code.code == "BANNED_USER"));

    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![plugin],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;

    assert!(context.db_schema.field("user", "role").is_ok());
    assert!(context.db_schema.field("user", "banned").is_ok());
    assert!(context
        .db_schema
        .field("session", "impersonated_by")
        .is_ok());
    Ok(())
}

#[tokio::test]
async fn default_role_hook_applies_to_core_user_creation() -> Result<(), Box<dyn std::error::Error>>
{
    let memory = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            plugins: vec![admin(AdminOptions::default())],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        Arc::new(memory.clone()),
    )?;
    let adapter = context.adapter().ok_or("missing adapter")?;

    DbUserStore::new(adapter.as_ref())
        .create_user(CreateUserInput::new("Plain User", "plain@example.com"))
        .await?;

    let users = memory.records("user").await;
    assert_eq!(
        users[0].get("role"),
        Some(&DbValue::String("user".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn banned_user_session_creation_is_blocked_globally() -> Result<(), Box<dyn std::error::Error>>
{
    let Fixture { context, .. } = fixture()?;
    let banned = create_user(&context, "banned@example.com", "user").await?;
    let expired = create_user(&context, "expired@example.com", "user").await?;
    let adapter = context.adapter().ok_or("missing adapter")?;
    adapter
        .update(
            openauth_core::db::Update::new("user")
                .where_clause(openauth_core::db::Where::new(
                    "id",
                    DbValue::String(banned.id.clone()),
                ))
                .data("banned", DbValue::Boolean(true))
                .data("ban_reason", DbValue::String("policy".to_owned())),
        )
        .await?;
    adapter
        .update(
            openauth_core::db::Update::new("user")
                .where_clause(openauth_core::db::Where::new(
                    "id",
                    DbValue::String(expired.id.clone()),
                ))
                .data("banned", DbValue::Boolean(true))
                .data(
                    "ban_expires",
                    DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::minutes(1)),
                ),
        )
        .await?;

    let blocked = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            banned.id,
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await;
    assert!(blocked.is_err());

    let allowed = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            expired.id.clone(),
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    assert_eq!(allowed.user_id, expired.id);
    Ok(())
}

#[tokio::test]
async fn non_admin_cannot_list_users() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        context, router, ..
    } = fixture()?;
    let user = create_user(&context, "user@example.com", "user").await?;
    let cookie = session_cookie(&context, &user.id).await?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/admin/list-users",
            None,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response)?["code"],
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"
    );
    Ok(())
}

#[tokio::test]
async fn admin_can_manage_user_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        context, router, ..
    } = fixture()?;
    let admin = create_user(&context, "admin@example.com", "admin").await?;
    let cookie = session_cookie(&context, &admin.id).await?;

    let created = router
        .handle_async(request(
            Method::POST,
            "/admin/create-user",
            Some(json!({
                "email": "managed@example.com",
                "name": "Managed",
                "password": "password123",
                "role": "user"
            })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(
        created.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(created.body())
    );
    let created = json_body(created)?;
    let user_id = created["user"]["id"].as_str().ok_or("missing user id")?;

    let role = router
        .handle_async(request(
            Method::POST,
            "/admin/set-role",
            Some(json!({ "userId": user_id, "role": "admin" })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(role.status(), StatusCode::OK);
    assert_eq!(json_body(role)?["user"]["role"], "admin");

    let list = router
        .handle_async(request(
            Method::GET,
            "/admin/list-users?searchValue=managed&searchField=email",
            None,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(json_body(list)?["total"], 1);

    let self_ban = router
        .handle_async(request(
            Method::POST,
            "/admin/ban-user",
            Some(json!({ "userId": admin.id })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(self_ban.status(), StatusCode::BAD_REQUEST);

    let ban = router
        .handle_async(request(
            Method::POST,
            "/admin/ban-user",
            Some(json!({ "userId": user_id, "banReason": "policy" })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(ban.status(), StatusCode::OK);
    assert_eq!(json_body(ban)?["user"]["banned"], true);

    let unban = router
        .handle_async(request(
            Method::POST,
            "/admin/unban-user",
            Some(json!({ "userId": user_id })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(unban.status(), StatusCode::OK);
    assert_eq!(json_body(unban)?["user"]["banned"], false);

    let remove = router
        .handle_async(request(
            Method::POST,
            "/admin/remove-user",
            Some(json!({ "userId": user_id })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(remove.status(), StatusCode::OK);
    assert_eq!(json_body(remove)?["success"], true);
    Ok(())
}

#[tokio::test]
async fn admin_can_manage_sessions_permissions_and_impersonation(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        context, router, ..
    } = fixture()?;
    let admin = create_user(&context, "admin@example.com", "admin").await?;
    let target = create_user(&context, "target@example.com", "user").await?;
    let admin_cookie = session_cookie(&context, &admin.id).await?;
    let target_session_cookie = session_cookie(&context, &target.id).await?;

    let sessions = router
        .handle_async(request(
            Method::POST,
            "/admin/list-user-sessions",
            Some(json!({ "userId": target.id })),
            Some(&admin_cookie),
        )?)
        .await?;
    assert_eq!(
        sessions.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(sessions.body())
    );
    assert_eq!(
        json_body(sessions)?["sessions"]
            .as_array()
            .ok_or("sessions")?
            .len(),
        1
    );

    let permission = router
        .handle_async(request(
            Method::POST,
            "/admin/has-permission",
            Some(json!({ "role": "admin", "permissions": { "user": ["create"] } })),
            None,
        )?)
        .await?;
    assert_eq!(permission.status(), StatusCode::OK);
    assert_eq!(json_body(permission)?["success"], true);

    let impersonated = router
        .handle_async(request(
            Method::POST,
            "/admin/impersonate-user",
            Some(json!({ "userId": target.id })),
            Some(&admin_cookie),
        )?)
        .await?;
    assert_eq!(impersonated.status(), StatusCode::OK);
    assert!(set_cookie_values(&impersonated)
        .iter()
        .any(|cookie| { cookie.starts_with("better-auth.admin_session=") }));
    let impersonation_cookie = cookie_header_from_response(&impersonated);
    let stop = router
        .handle_async(request(
            Method::POST,
            "/admin/stop-impersonating",
            None,
            Some(&impersonation_cookie),
        )?)
        .await?;
    assert_eq!(stop.status(), StatusCode::OK);

    let revoke = router
        .handle_async(request(
            Method::POST,
            "/admin/revoke-user-sessions",
            Some(json!({ "userId": target.id })),
            Some(&admin_cookie),
        )?)
        .await?;
    assert_eq!(revoke.status(), StatusCode::OK);

    let _ = target_session_cookie;
    Ok(())
}

struct Fixture {
    context: AuthContext,
    router: AuthRouter,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            plugins: vec![admin(AdminOptions::default())],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    let router = AuthRouter::with_async_endpoints(context.clone(), Vec::new(), Vec::new())?;
    Ok(Fixture { context, router })
}

struct TestUser {
    id: String,
}

async fn create_user(
    context: &AuthContext,
    email: &str,
    role: &str,
) -> Result<TestUser, Box<dyn std::error::Error>> {
    let adapter = context.adapter().ok_or("missing adapter")?;
    let id = openauth_core::crypto::random::generate_random_string(32);
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(id.clone()))
                .data(
                    "name",
                    DbValue::String(email.split('@').next().unwrap_or(email).to_owned()),
                )
                .data("email", DbValue::String(email.to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("role", DbValue::String(role.to_owned()))
                .data("banned", DbValue::Boolean(false))
                .data("ban_reason", DbValue::Null)
                .data("ban_expires", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    Ok(TestUser { id })
}

async fn session_cookie(
    context: &AuthContext,
    user_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let adapter = context.adapter().ok_or("missing adapter")?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            user_id,
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    Ok(format!(
        "{}={}",
        context.auth_cookies.session_token.name,
        sign_cookie_value(&session.token, &context.secret)?
    ))
}

fn request(
    method: Method,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error>> {
    let needs_origin = method != Method::GET && cookie.is_some();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000/api/auth{path}"));
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if needs_origin {
        builder = builder.header(header::ORIGIN, "http://localhost:3000");
    }
    Ok(builder.body(match body {
        Some(value) => serde_json::to_vec(&value)?,
        None => Vec::new(),
    })?)
}

fn json_body(response: ApiResponse) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(response.body())?)
}

fn set_cookie_values(response: &ApiResponse) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

fn cookie_header_from_response(response: &ApiResponse) -> String {
    set_cookie_values(response)
        .into_iter()
        .filter_map(|cookie| cookie.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>()
        .join("; ")
}

fn secret() -> String {
    "secret-a-at-least-32-chars-long!!".to_owned()
}
