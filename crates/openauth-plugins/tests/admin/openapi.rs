use std::sync::Arc;

use openauth_core::api::AuthRouter;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::admin::{admin, admin_with, AdminOptions, AdminSchemaOptions};

#[test]
fn custom_schema_overrides_change_physical_field_names() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![admin_with(AdminOptions {
                schema: AdminSchemaOptions {
                    user_role_field: "admin_role".to_owned(),
                    user_banned_field: "is_banned".to_owned(),
                    user_ban_reason_field: "ban_note".to_owned(),
                    user_ban_expires_field: "ban_until".to_owned(),
                    session_impersonated_by_field: "impersonator_id".to_owned(),
                },
                ..AdminOptions::default()
            })],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;

    assert_eq!(context.db_schema.field("user", "role")?.name, "admin_role");
    assert_eq!(context.db_schema.field("user", "banned")?.name, "is_banned");
    assert_eq!(
        context.db_schema.field("user", "ban_reason")?.name,
        "ban_note"
    );
    assert_eq!(
        context.db_schema.field("user", "ban_expires")?.name,
        "ban_until"
    );
    assert_eq!(
        context.db_schema.field("session", "impersonated_by")?.name,
        "impersonator_id"
    );
    Ok(())
}

#[test]
fn admin_endpoints_expose_detailed_openapi() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            plugins: vec![admin()],
            secret: Some(secret()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), Vec::new())?;
    let openapi = router.openapi_schema();

    let create_user = &openapi["paths"]["/admin/create-user"]["post"];
    assert_eq!(create_user["operationId"], "createUser");
    assert!(create_user["tags"]
        .as_array()
        .ok_or("missing tags")?
        .iter()
        .any(|tag| tag == "Admin"));
    assert_eq!(
        create_user["requestBody"]["content"]["application/json"]["schema"]["properties"]
            ["password"]["minLength"],
        8
    );
    assert_eq!(
        create_user["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["user"]["$ref"],
        "#/components/schemas/User"
    );

    let list_users = &openapi["paths"]["/admin/list-users"]["get"];
    assert_eq!(list_users["operationId"], "listUsers");
    let parameters = list_users["parameters"]
        .as_array()
        .ok_or("missing parameters")?;
    assert!(parameters
        .iter()
        .any(|parameter| parameter["name"] == "searchValue"));
    assert!(parameters
        .iter()
        .any(|parameter| parameter["name"] == "filterOperator"));
    assert_eq!(
        list_users["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["users"]["items"]["$ref"],
        "#/components/schemas/User"
    );

    let impersonate = &openapi["paths"]["/admin/impersonate-user"]["post"];
    assert_eq!(impersonate["operationId"], "impersonateUser");
    assert_eq!(
        impersonate["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["session"]["$ref"],
        "#/components/schemas/Session"
    );
    Ok(())
}

fn secret() -> String {
    "secret-a-at-least-32-chars-long!!".to_owned()
}
