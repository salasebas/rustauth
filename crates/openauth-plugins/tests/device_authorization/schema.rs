use super::*;

#[test]
fn exposes_device_authorization_plugin_id() {
    assert_eq!(
        openauth_plugins::device_authorization::UPSTREAM_PLUGIN_ID,
        "device-authorization"
    );
}

#[test]
fn schema_contributes_device_code_table() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![device_authorization_with(
                DeviceAuthorizationOptions::default(),
            )],
            secret: Some(secret().to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter,
    )?;

    let table = context
        .db_schema
        .table("device_code")
        .ok_or("missing table")?;
    assert_eq!(table.name, "device_codes");
    assert!(table.field("device_code").is_some_and(|field| field.unique));
    assert!(table.field("user_code").is_some_and(|field| field.unique));
    assert_eq!(
        table.field("device_code").map(|field| field.name.as_str()),
        Some("device_code")
    );
    assert_eq!(
        table.field("user_code").map(|field| field.name.as_str()),
        Some("user_code")
    );
    assert_eq!(
        table.field("user_id").map(|field| field.name.as_str()),
        Some("user_id")
    );
    assert_eq!(
        table.field("expires_at").map(|field| field.name.as_str()),
        Some("expires_at")
    );
    Ok(())
}

#[test]
fn schema_options_customize_physical_table_and_field_names(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![device_authorization_with(
                DeviceAuthorizationOptions::default().schema(
                    openauth_plugins::device_authorization::DeviceAuthorizationSchemaOptions::new()
                        .table_name("oauth_device_codes")
                        .field_name("device_code", "device_code")
                        .field_name("user_code", "user_code"),
                ),
            )],
            secret: Some(secret().to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter,
    )?;

    let table = context
        .db_schema
        .table("device_code")
        .ok_or("missing table")?;
    assert_eq!(table.name, "oauth_device_codes");
    assert_eq!(
        table.field("device_code").map(|field| field.name.as_str()),
        Some("device_code")
    );
    assert_eq!(
        table.field("user_code").map(|field| field.name.as_str()),
        Some("user_code")
    );
    Ok(())
}

#[test]
fn router_registers_all_device_authorization_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, DeviceAuthorizationOptions::default())?;
    let registry = router.endpoint_registry();

    for (method, path) in [
        (Method::POST, "/device/code"),
        (Method::POST, "/device/token"),
        (Method::GET, "/device"),
        (Method::POST, "/device/approve"),
        (Method::POST, "/device/deny"),
    ] {
        assert!(registry
            .iter()
            .any(|endpoint| endpoint.method == method && endpoint.path == path));
    }
    Ok(())
}
