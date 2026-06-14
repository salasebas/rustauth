use rustauth_core::db::{
    auth_schema, AuthSchema, AuthSchemaOptions, DbValue, MemoryAdapter, SchemaAdapter, TableOptions,
};
use rustauth_core::error::RustAuthError;
use rustauth_core::user::{CreateUserInput, DbUserStore};

#[test]
fn map_record_to_logical_renames_physical_columns() -> Result<(), RustAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default().with_field_name("email", "primary_email"),
        ..AuthSchemaOptions::default()
    });

    let mut record = rustauth_core::db::DbRecord::new();
    record.insert("id".to_owned(), DbValue::String("user_1".to_owned()));
    record.insert(
        "primary_email".to_owned(),
        DbValue::String("ada@example.com".to_owned()),
    );

    let mapped = schema.map_record_to_logical("user", record)?;
    assert_eq!(
        mapped.get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    Ok(())
}

#[test]
fn map_record_to_logical_preserves_unknown_columns() -> Result<(), RustAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let mut record = rustauth_core::db::DbRecord::new();
    record.insert("custom".to_owned(), DbValue::String("value".to_owned()));

    let mapped = schema.map_record_to_logical("user", record)?;
    assert_eq!(
        mapped.get("custom"),
        Some(&DbValue::String("value".to_owned()))
    );
    Ok(())
}

#[test]
fn schema_table_where_eq_rejects_unknown_field() -> Result<(), RustAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let users = AuthSchema::new(&schema).table("user")?;

    assert_eq!(
        users.where_eq("missing_field", DbValue::String("x".to_owned())),
        Err(RustAuthError::FieldNotFound {
            table: "user".to_owned(),
            field: "missing_field".to_owned(),
        })
    );
    Ok(())
}

#[test]
fn schema_table_rejects_unknown_table() {
    let schema = auth_schema(AuthSchemaOptions::default());
    assert!(matches!(
        AuthSchema::new(&schema).table("missing"),
        Err(RustAuthError::TableNotFound { table }) if table == "missing"
    ));
}

#[tokio::test]
async fn user_store_maps_renamed_columns_through_schema_adapter() -> Result<(), RustAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_name("app_users")
            .with_field_name("email", "primary_email"),
        ..AuthSchemaOptions::default()
    });
    let adapter = SchemaAdapter::new(schema.clone(), MemoryAdapter::new());
    let store = DbUserStore::with_schema(&adapter, schema);

    let user = store
        .create_user(CreateUserInput {
            name: "Ada".to_owned(),
            email: "ada@example.com".to_owned(),
            email_verified: true,
            image: None,
            username: None,
            display_username: None,
            id: Some("user_1".to_owned()),
            additional_fields: Default::default(),
        })
        .await?;

    assert_eq!(user.email, "ada@example.com");

    let found = store
        .find_user_by_email("ada@example.com")
        .await?
        .ok_or_else(|| RustAuthError::Adapter("missing user".to_owned()))?;
    assert_eq!(found.id, "user_1");

    let physical = adapter
        .inner()
        .records("app_users")
        .await
        .into_iter()
        .next()
        .ok_or_else(|| RustAuthError::Adapter("missing physical record".to_owned()))?;
    assert_eq!(
        physical.get("primary_email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );

    Ok(())
}

#[test]
fn schema_table_ensure_fields_validates_select_lists() -> Result<(), RustAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let users = AuthSchema::new(&schema).table("user")?;

    assert_eq!(
        users.ensure_fields(["email", "missing"]),
        Err(RustAuthError::FieldNotFound {
            table: "user".to_owned(),
            field: "missing".to_owned(),
        })
    );
    Ok(())
}

#[test]
fn auth_context_exposes_schema_aware_stores() -> Result<(), RustAuthError> {
    use rustauth_core::context::create_auth_context_with_adapter;
    use rustauth_core::options::RustAuthOptions;
    use std::sync::Arc;

    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(RustAuthOptions::default(), adapter)?;
    let _users = context.users()?;
    let _sessions = context.sessions()?;
    let _verifications = context.verifications()?;
    Ok(())
}
