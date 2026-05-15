use std::collections::BTreeMap;
use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbValue, MemoryAdapter};
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::admin::{admin, AdminOptions, PermissionMap, Role};
use serde_json::json;

use super::{create_user, json_body, request, secret, session_cookie, set_cookie_values, Fixture};

#[tokio::test]
async fn create_user_requires_admin_session_for_http_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { router, .. } = super::fixture()?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/admin/create-user",
            Some(json!({
                "email": "public-create@example.com",
                "name": "Public Create"
            })),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn admin_can_create_user_without_password_and_with_custom_data(
) -> Result<(), Box<dyn std::error::Error>> {
    let memory = MemoryAdapter::new();
    let Fixture { context, router } =
        fixture_with_options(AdminOptions::default(), memory.clone())?;
    let admin = create_user(&context, "admin-create@example.com", "admin").await?;
    let cookie = session_cookie(&context, &admin.id).await?;

    let created = router
        .handle_async(request(
            Method::POST,
            "/admin/create-user",
            Some(json!({
                "email": "custom-data@example.com",
                "name": "Custom Data",
                "role": ["user", "admin"],
                "data": {
                    "nickname": "cd",
                    "login_count": 7,
                    "newsletter": true
                }
            })),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(json_body(created)?["user"]["role"], "user,admin");
    let records = memory.records("user").await;
    let custom = records
        .iter()
        .find(|record| {
            record.get("email") == Some(&DbValue::String("custom-data@example.com".to_owned()))
        })
        .ok_or("missing custom user")?;
    assert_eq!(
        custom.get("nickname"),
        Some(&DbValue::String("cd".to_owned()))
    );
    assert_eq!(custom.get("login_count"), Some(&DbValue::Number(7)));
    assert_eq!(custom.get("newsletter"), Some(&DbValue::Boolean(true)));
    Ok(())
}

#[tokio::test]
async fn create_user_rejects_reserved_custom_data_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let Fixture { context, router } = super::fixture()?;
    let admin = create_user(&context, "admin-reserved@example.com", "admin").await?;
    let cookie = session_cookie(&context, &admin.id).await?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/admin/create-user",
            Some(json!({
                "email": "reserved@example.com",
                "name": "Reserved",
                "data": { "role": "admin" }
            })),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn list_users_supports_typed_filters_search_sort_and_pagination(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { context, router } = super::fixture()?;
    let admin = create_user(&context, "admin-list@example.com", "admin").await?;
    let alpha = create_user(&context, "sort-alpha@example.com", "user").await?;
    let beta = create_user(&context, "sort-beta@example.com", "user").await?;
    let zulu = create_user(&context, "sort-zulu@example.com", "user").await?;
    let cookie = session_cookie(&context, &admin.id).await?;
    let adapter = context.adapter().ok_or("missing adapter")?;
    adapter
        .update(
            openauth_core::db::Update::new("user")
                .where_clause(openauth_core::db::Where::new(
                    "id",
                    DbValue::String(alpha.id.clone()),
                ))
                .data("banned", DbValue::Boolean(true)),
        )
        .await?;

    let unbanned = router
        .handle_async(request(
            Method::GET,
            "/admin/list-users?filterField=banned&filterValue=false",
            None,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(unbanned.status(), StatusCode::OK);
    let unbanned = json_body(unbanned)?;
    assert!(unbanned["users"]
        .as_array()
        .ok_or("users")?
        .iter()
        .all(|user| user["banned"] == false));

    let ne = router
        .handle_async(request(
            Method::GET,
            &format!(
                "/admin/list-users?filterField=_id&filterOperator=ne&filterValue={}",
                beta.id
            ),
            None,
            Some(&cookie),
        )?)
        .await?;
    let ne = json_body(ne)?;
    assert!(ne["users"]
        .as_array()
        .ok_or("users")?
        .iter()
        .all(|user| user["id"] != beta.id));

    let sorted = router
        .handle_async(request(
            Method::GET,
            "/admin/list-users?searchValue=sort-&searchField=email&filterField=role&filterOperator=eq&filterValue=user&sortBy=name&sortDirection=desc&limit=2&offset=0",
            None,
            Some(&cookie),
        )?)
        .await?;
    let sorted = json_body(sorted)?;
    let users = sorted["users"].as_array().ok_or("users")?;
    assert_eq!(users.len(), 2);
    assert_eq!(users[0]["id"], zulu.id);
    assert_eq!(users[1]["id"], beta.id);
    Ok(())
}

#[tokio::test]
async fn set_role_accepts_multiple_roles_and_rejects_unknown_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { context, router } = super::fixture()?;
    let admin = create_user(&context, "admin-role@example.com", "admin").await?;
    let target = create_user(&context, "target-role@example.com", "user").await?;
    let cookie = session_cookie(&context, &admin.id).await?;

    let multiple = router
        .handle_async(request(
            Method::POST,
            "/admin/set-role",
            Some(json!({ "userId": target.id, "role": ["user", "admin"] })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(multiple.status(), StatusCode::OK);
    assert_eq!(json_body(multiple)?["user"]["role"], "user,admin");

    let unknown = router
        .handle_async(request(
            Method::POST,
            "/admin/set-role",
            Some(json!({ "userId": target.id, "role": ["user", "unknown"] })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(unknown)?["code"],
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"
    );
    Ok(())
}

#[tokio::test]
async fn update_user_rejects_role_change_without_set_role_permission(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = AdminOptions {
        roles: BTreeMap::from([
            ("admin".to_owned(), admin_role()),
            ("user".to_owned(), Role::new(PermissionMap::new())),
            (
                "support".to_owned(),
                Role::new(PermissionMap::from([(
                    "user".to_owned(),
                    vec!["update".to_owned()],
                )])),
            ),
        ]),
        ..AdminOptions::default()
    };
    let Fixture { context, router } = fixture_with_options(options, MemoryAdapter::new())?;
    let support = create_user(&context, "support@example.com", "support").await?;
    let target = create_user(&context, "support-target@example.com", "user").await?;
    let cookie = session_cookie(&context, &support.id).await?;

    let ok = router
        .handle_async(request(
            Method::POST,
            "/admin/update-user",
            Some(json!({ "userId": target.id, "data": { "name": "Support Updated" } })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(ok.status(), StatusCode::OK);

    let denied = router
        .handle_async(request(
            Method::POST,
            "/admin/update-user",
            Some(json!({ "userId": target.id, "data": { "role": "admin" } })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn impersonation_admin_target_permissions_match_upstream(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { context, router } = super::fixture()?;
    let admin_user = create_user(&context, "admin-imp@example.com", "admin").await?;
    let target_admin = create_user(&context, "target-admin-imp@example.com", "admin").await?;
    let cookie = session_cookie(&context, &admin_user.id).await?;

    let blocked = router
        .handle_async(request(
            Method::POST,
            "/admin/impersonate-user",
            Some(json!({ "userId": target_admin.id })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(blocked)?["code"], "YOU_CANNOT_IMPERSONATE_ADMINS");

    let super_options = AdminOptions {
        roles: BTreeMap::from([
            ("admin".to_owned(), admin_role()),
            ("user".to_owned(), Role::new(PermissionMap::new())),
            (
                "super-admin".to_owned(),
                Role::new(PermissionMap::from([
                    (
                        "user".to_owned(),
                        vec!["impersonate".to_owned(), "impersonate-admins".to_owned()],
                    ),
                    ("session".to_owned(), vec![]),
                ])),
            ),
        ]),
        ..AdminOptions::default()
    };
    let Fixture {
        context: super_context,
        router: super_router,
    } = fixture_with_options(super_options, MemoryAdapter::new())?;
    let super_admin = create_user(&super_context, "super-admin@example.com", "super-admin").await?;
    let target = create_user(&super_context, "target-admin@example.com", "admin").await?;
    let super_cookie = session_cookie(&super_context, &super_admin.id).await?;
    let allowed = super_router
        .handle_async(request(
            Method::POST,
            "/admin/impersonate-user",
            Some(json!({ "userId": target.id })),
            Some(&super_cookie),
        )?)
        .await?;
    assert_eq!(allowed.status(), StatusCode::OK);

    let Fixture {
        context: legacy_context,
        router: legacy_router,
    } = fixture_with_options(
        AdminOptions {
            allow_impersonating_admins: true,
            ..AdminOptions::default()
        },
        MemoryAdapter::new(),
    )?;
    let legacy_admin = create_user(&legacy_context, "legacy-admin@example.com", "admin").await?;
    let legacy_target = create_user(&legacy_context, "legacy-target@example.com", "admin").await?;
    let legacy_cookie = session_cookie(&legacy_context, &legacy_admin.id).await?;
    let legacy_allowed = legacy_router
        .handle_async(request(
            Method::POST,
            "/admin/impersonate-user",
            Some(json!({ "userId": legacy_target.id })),
            Some(&legacy_cookie),
        )?)
        .await?;
    assert_eq!(legacy_allowed.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn core_list_sessions_filters_impersonated_sessions() -> Result<(), Box<dyn std::error::Error>>
{
    let memory = MemoryAdapter::new();
    let adapter = Arc::new(memory.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            plugins: vec![admin(AdminOptions::default())],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(adapter),
    )?;
    let admin_user = create_user(&context, "core-admin@example.com", "admin").await?;
    let target = create_user(&context, "core-target@example.com", "user").await?;
    let cookie = session_cookie(&context, &target.id).await?;
    let admin_cookie = session_cookie(&context, &admin_user.id).await?;
    let impersonated = router
        .handle_async(request(
            Method::POST,
            "/admin/impersonate-user",
            Some(json!({ "userId": target.id })),
            Some(&admin_cookie),
        )?)
        .await?;
    assert_eq!(impersonated.status(), StatusCode::OK);
    assert!(!set_cookie_values(&impersonated).is_empty());

    let listed = router
        .handle_async(request(Method::GET, "/list-sessions", None, Some(&cookie))?)
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let sessions = json_body(listed)?;
    assert_eq!(sessions.as_array().ok_or("sessions")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn set_user_password_rejects_invalid_lengths_and_empty_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture { context, router } = super::fixture()?;
    let admin = create_user(&context, "password-admin@example.com", "admin").await?;
    let target = create_user(&context, "password-target@example.com", "user").await?;
    let cookie = session_cookie(&context, &admin.id).await?;

    for (user_id, password) in [
        ("", "newPassword"),
        (target.id.as_str(), ""),
        (target.id.as_str(), "1234567"),
    ] {
        let response = router
            .handle_async(request(
                Method::POST,
                "/admin/set-user-password",
                Some(json!({ "userId": user_id, "newPassword": password })),
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let long_password = "a".repeat(129);
    let response = router
        .handle_async(request(
            Method::POST,
            "/admin/set-user-password",
            Some(json!({ "userId": target.id, "newPassword": long_password })),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "PASSWORD_TOO_LONG");
    Ok(())
}

fn fixture_with_options(
    options: AdminOptions,
    memory: MemoryAdapter,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            plugins: vec![admin(options)],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        Arc::new(memory),
    )?;
    let router = AuthRouter::with_async_endpoints(context.clone(), Vec::new(), Vec::new())?;
    Ok(Fixture { context, router })
}

fn admin_role() -> Role {
    Role::new(PermissionMap::from([
        (
            "user".to_owned(),
            vec![
                "create".to_owned(),
                "list".to_owned(),
                "set-role".to_owned(),
                "ban".to_owned(),
                "impersonate".to_owned(),
                "delete".to_owned(),
                "set-password".to_owned(),
                "get".to_owned(),
                "update".to_owned(),
            ],
        ),
        (
            "session".to_owned(),
            vec!["list".to_owned(), "revoke".to_owned(), "delete".to_owned()],
        ),
    ]))
}
