use rustauth_core::db::{
    auth_schema, AuthSchemaOptions, DbField, DbFieldType, IdGeneration, IdPolicy, RateLimitStorage,
    TableOptions,
};
use rustauth_core::error::RustAuthError;

#[test]
fn auth_schema_uses_plural_table_names_by_default() {
    let schema = auth_schema(AuthSchemaOptions::default());

    assert_eq!(
        schema.table("user").map(|table| table.name.as_str()),
        Some("users")
    );
    assert_eq!(
        schema.table("account").map(|table| table.name.as_str()),
        Some("accounts")
    );
    assert_eq!(
        schema.table("session").map(|table| table.name.as_str()),
        Some("sessions")
    );
    assert_eq!(
        schema
            .table("verification")
            .map(|table| table.name.as_str()),
        Some("verifications")
    );
}

#[test]
fn auth_schema_uses_snake_case_column_names_by_default() {
    let schema = auth_schema(AuthSchemaOptions::default());

    assert_eq!(
        schema
            .table("account")
            .and_then(|table| table.field("refresh_token_expires_at"))
            .map(|field| field.name.as_str()),
        Some("refresh_token_expires_at")
    );
    assert_eq!(
        schema
            .table("account")
            .and_then(|table| table.field("access_token_expires_at"))
            .map(|field| field.name.as_str()),
        Some("access_token_expires_at")
    );
}

#[test]
fn auth_schema_uses_custom_refresh_token_expiry_field_name() {
    let schema = auth_schema(AuthSchemaOptions {
        account: TableOptions::default().with_field_name(
            "refresh_token_expires_at",
            "custom_refresh_token_expires_at",
        ),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(
        schema
            .table("account")
            .and_then(|table| table.field("refresh_token_expires_at"))
            .map(|field| field.name.as_str()),
        Some("custom_refresh_token_expires_at")
    );
}

#[test]
fn auth_schema_keeps_access_and_refresh_expiry_overrides_separate() {
    let schema = auth_schema(AuthSchemaOptions {
        account: TableOptions::default()
            .with_field_name("access_token_expires_at", "custom_access_token_expires_at")
            .with_field_name(
                "refresh_token_expires_at",
                "custom_refresh_token_expires_at",
            ),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(
        schema
            .table("account")
            .and_then(|table| table.field("access_token_expires_at"))
            .map(|field| field.name.as_str()),
        Some("custom_access_token_expires_at")
    );
    assert_eq!(
        schema
            .table("account")
            .and_then(|table| table.field("refresh_token_expires_at"))
            .map(|field| field.name.as_str()),
        Some("custom_refresh_token_expires_at")
    );
}

#[test]
fn auth_schema_merges_additional_verification_fields() {
    let schema = auth_schema(AuthSchemaOptions {
        verification: TableOptions::default()
            .with_field("new_field", DbField::new("new_field", DbFieldType::String)),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(
        schema
            .table("verification")
            .and_then(|table| table.field("new_field"))
            .map(|field| field.name.as_str()),
        Some("new_field")
    );
}

#[test]
fn auth_schema_excludes_verification_table_when_secondary_storage_is_configured() {
    let schema = auth_schema(AuthSchemaOptions {
        has_secondary_storage: true,
        ..AuthSchemaOptions::default()
    });

    assert!(schema.table("verification").is_none());
}

#[test]
fn auth_schema_includes_verification_table_when_store_in_database_is_true() {
    let schema = auth_schema(AuthSchemaOptions {
        has_secondary_storage: true,
        store_verification_in_database: true,
        ..AuthSchemaOptions::default()
    });

    assert!(schema.table("verification").is_some());
}

#[test]
fn auth_schema_includes_rate_limits_only_for_database_storage() {
    let memory_schema = auth_schema(AuthSchemaOptions::default());
    let database_schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });

    assert!(memory_schema.table("rate_limit").is_none());
    assert_eq!(
        database_schema
            .table("rate_limit")
            .map(|table| table.name.as_str()),
        Some("rate_limits")
    );
}

#[test]
fn auth_schema_resolves_table_name_from_logical_or_database_name() {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default().with_name("app_users"),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(schema.table_name("user"), Ok("app_users"));
    assert_eq!(schema.table_name("app_users"), Ok("app_users"));
}

#[test]
fn auth_schema_resolves_field_name_from_logical_or_database_name() {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default().with_field_name("email", "primary_email"),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(schema.field_name("user", "email"), Ok("primary_email"));
    assert_eq!(
        schema.field_name("users", "primary_email"),
        Ok("primary_email")
    );
}

#[test]
fn auth_schema_returns_typed_error_for_unknown_table() {
    let schema = auth_schema(AuthSchemaOptions::default());

    assert_eq!(
        schema.table_name("missing"),
        Err(RustAuthError::TableNotFound {
            table: "missing".to_owned()
        })
    );
}

#[test]
fn auth_schema_returns_typed_error_for_unknown_field() {
    let schema = auth_schema(AuthSchemaOptions::default());

    assert_eq!(
        schema.field_name("user", "missing"),
        Err(RustAuthError::FieldNotFound {
            table: "user".to_owned(),
            field: "missing".to_owned()
        })
    );
}

#[test]
fn auth_schema_uses_physical_user_table_in_account_foreign_key() {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default().with_name("app_users"),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(
        schema
            .field("account", "user_id")
            .ok()
            .and_then(|field| field.foreign_key.as_ref())
            .map(|foreign_key| foreign_key.table.as_str()),
        Some("app_users")
    );
}

#[test]
fn auth_schema_applies_serial_id_policy_to_core_tables() {
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Serial),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(
        schema.field("user", "id").map(|field| &field.field_type),
        Ok(&DbFieldType::Number)
    );
    assert_eq!(
        schema.field("account", "id").map(|field| field.required),
        Ok(false)
    );
    assert_eq!(
        schema
            .field("account", "user_id")
            .map(|field| &field.field_type),
        Ok(&DbFieldType::Number)
    );
    assert_eq!(
        schema
            .field("session", "user_id")
            .map(|field| &field.field_type),
        Ok(&DbFieldType::Number)
    );
}

#[test]
fn auth_schema_marks_uuid_id_optional_when_database_generates_uuid() {
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Uuid).with_database_uuid_support(true),
        ..AuthSchemaOptions::default()
    });

    assert_eq!(
        schema.field("user", "id").map(|field| &field.field_type),
        Ok(&DbFieldType::String)
    );
    assert_eq!(
        schema.field("user", "id").map(|field| field.required),
        Ok(false)
    );
}
