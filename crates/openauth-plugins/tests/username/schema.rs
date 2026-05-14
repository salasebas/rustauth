use openauth_core::context::create_auth_context;
use openauth_core::options::OpenAuthOptions;

#[test]
fn username_plugin_registers_schema_and_errors() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![openauth_plugins::username::username()],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let username = context.db_schema.field("user", "username")?;
    assert_eq!(username.name, "username");
    assert!(!username.required);
    assert!(username.unique);
    assert!(username.returned);

    let display_username = context.db_schema.field("user", "display_username")?;
    assert_eq!(display_username.name, "display_username");
    assert!(!display_username.required);
    assert!(display_username.returned);

    assert_eq!(
        context
            .plugin_error_codes
            .get("INVALID_USERNAME_OR_PASSWORD")
            .map(|code| code.message.as_str()),
        Some("Invalid username or password")
    );
    Ok(())
}
