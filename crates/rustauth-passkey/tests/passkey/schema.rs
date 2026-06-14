use rustauth_core::context::create_auth_context;
use rustauth_core::db::DbFieldType;
use rustauth_core::options::RustAuthOptions;
use rustauth_passkey::{passkey, PasskeyOptions, PasskeySchemaOptions};

#[test]
fn passkey_plugin_registers_snake_case_plural_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![passkey(PasskeyOptions::default())],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("passkey")
        .ok_or("missing passkey table")?;
    assert_eq!(table.name, "passkeys");

    let public_key = context.db_schema.field("passkey", "public_key")?;
    assert_eq!(public_key.name, "public_key");
    assert_eq!(public_key.field_type, DbFieldType::String);
    assert!(public_key.required);

    let credential_id = context.db_schema.field("passkey", "credential_id")?;
    assert_eq!(credential_id.name, "credential_id");
    assert!(credential_id.index);
    assert!(credential_id.unique);

    let user_id = context.db_schema.field("passkey", "user_id")?;
    assert_eq!(user_id.name, "user_id");
    assert!(user_id.index);
    assert!(user_id.foreign_key.is_some());

    let credential = context.db_schema.field("passkey", "webauthn_credential")?;
    assert_eq!(credential.field_type, DbFieldType::Json);
    assert!(!credential.returned);

    assert_eq!(
        context
            .plugin_error_codes
            .get("CHALLENGE_NOT_FOUND")
            .map(|code| code.message.as_str()),
        Some("Challenge not found")
    );

    Ok(())
}

#[test]
fn passkey_schema_options_rename_table_and_database_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![passkey(
            PasskeyOptions::default().schema(
                PasskeySchemaOptions::new()
                    .table_name("auth_passkeys")
                    .field_name("public_key", "publicKey")
                    .field_name("credential_id", "credentialID")
                    .field_name("user_id", "userId")
                    .field_name("device_type", "deviceType")
                    .field_name("backed_up", "backedUp"),
            ),
        )],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("passkey")
        .ok_or("missing passkey table")?;
    assert_eq!(table.name, "auth_passkeys");

    assert_eq!(
        context.db_schema.field_name("passkey", "public_key")?,
        "publicKey"
    );
    assert_eq!(
        context.db_schema.field_name("passkey", "credential_id")?,
        "credentialID"
    );
    assert_eq!(
        context.db_schema.field_name("auth_passkeys", "user_id")?,
        "userId"
    );
    assert_eq!(
        context.db_schema.field_name("passkey", "device_type")?,
        "deviceType"
    );
    assert_eq!(
        context.db_schema.field_name("passkey", "backed_up")?,
        "backedUp"
    );

    let credential_id = context.db_schema.field("passkey", "credential_id")?;
    assert_eq!(credential_id.field_type, DbFieldType::String);
    assert!(credential_id.index);
    assert!(credential_id.unique);

    Ok(())
}
