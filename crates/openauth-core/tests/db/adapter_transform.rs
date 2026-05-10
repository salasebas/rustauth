use openauth_core::db::{
    auth_schema, resolve_join_options, transform_count_query, transform_create_query,
    transform_create_query_with_capabilities, transform_delete_many_query,
    transform_find_many_query, transform_find_many_query_with_capabilities, transform_update_query,
    transform_update_query_with_capabilities, AdapterCapabilities, AuthSchemaOptions, Count,
    Create, DbField, DbFieldType, DbValue, DeleteMany, FindMany, JoinOption, JoinRelation,
    RateLimitStorage, TableOptions, Update, Where,
};
use openauth_core::error::OpenAuthError;
use serde_json::json;
use time::OffsetDateTime;

#[test]
fn transform_create_query_maps_logical_names_to_physical_names() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_name("app_users")
            .with_field_name("email", "primary_email"),
        ..AuthSchemaOptions::default()
    });
    let query = Create::new("user")
        .data("email", DbValue::String("a@example.com".to_owned()))
        .select(["id", "email"]);

    let transformed = transform_create_query(&schema, query)?;

    assert_eq!(transformed.model, "app_users");
    assert_eq!(
        transformed.data.get("primary_email"),
        Some(&DbValue::String("a@example.com".to_owned()))
    );
    assert_eq!(
        transformed.select,
        vec!["id".to_owned(), "primary_email".to_owned()]
    );

    Ok(())
}

#[test]
fn transform_find_many_query_maps_where_sort_and_select_fields() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        session: TableOptions::default().with_field_name("user_id", "owner_id"),
        ..AuthSchemaOptions::default()
    });
    let query = FindMany::new("session")
        .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned())))
        .sort_by(openauth_core::db::Sort::new(
            "expires_at",
            openauth_core::db::SortDirection::Asc,
        ))
        .select(["id", "user_id"]);

    let transformed = transform_find_many_query(&schema, query)?;

    assert_eq!(transformed.model, "sessions");
    assert_eq!(transformed.where_clauses[0].field, "owner_id");
    assert_eq!(
        transformed.sort_by.as_ref().map(|sort| sort.field.as_str()),
        Some("expires_at")
    );
    assert_eq!(
        transformed.select,
        vec!["id".to_owned(), "owner_id".to_owned()]
    );

    Ok(())
}

#[test]
fn transform_update_query_maps_update_data_and_where_fields() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default().with_field_name("name", "display_name"),
        ..AuthSchemaOptions::default()
    });
    let query = Update::new("user")
        .where_clause(Where::new(
            "email",
            DbValue::String("a@example.com".to_owned()),
        ))
        .data("name", DbValue::String("Ada".to_owned()));

    let transformed = transform_update_query(&schema, query)?;

    assert_eq!(transformed.model, "users");
    assert_eq!(transformed.where_clauses[0].field, "email");
    assert_eq!(
        transformed.data.get("display_name"),
        Some(&DbValue::String("Ada".to_owned()))
    );

    Ok(())
}

#[test]
fn transform_count_and_delete_many_queries_map_where_fields() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        account: TableOptions::default().with_field_name("account_id", "provider_account_id"),
        ..AuthSchemaOptions::default()
    });

    let count = transform_count_query(
        &schema,
        Count::new("account").where_clause(Where::new(
            "account_id",
            DbValue::String("account_1".to_owned()),
        )),
    )?;
    let delete_many = transform_delete_many_query(
        &schema,
        DeleteMany::new("account").where_clause(Where::new(
            "account_id",
            DbValue::String("account_1".to_owned()),
        )),
    )?;

    assert_eq!(count.where_clauses[0].field, "provider_account_id");
    assert_eq!(delete_many.where_clauses[0].field, "provider_account_id");

    Ok(())
}

#[test]
fn transform_query_returns_typed_error_for_unknown_field() {
    let schema = auth_schema(AuthSchemaOptions::default());
    let query = Create::new("user").data("missing", DbValue::String("value".to_owned()));

    assert_eq!(
        transform_create_query(&schema, query),
        Err(OpenAuthError::FieldNotFound {
            table: "user".to_owned(),
            field: "missing".to_owned()
        })
    );
}

#[test]
fn transform_create_query_converts_booleans_when_adapter_lacks_boolean_support(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let capabilities = AdapterCapabilities::new("legacy-sql").without_booleans();
    let query = Create::new("user").data("email_verified", DbValue::Boolean(true));

    let transformed = transform_create_query_with_capabilities(&schema, &capabilities, query)?;

    assert_eq!(
        transformed.data.get("email_verified"),
        Some(&DbValue::Number(1))
    );

    Ok(())
}

#[test]
fn transform_find_many_query_coerces_number_strings_in_where_clauses() -> Result<(), OpenAuthError>
{
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let capabilities = AdapterCapabilities::new("sql");
    let query = FindMany::new("rate_limit")
        .where_clause(Where::new("count", DbValue::String("42".to_owned())));

    let transformed = transform_find_many_query_with_capabilities(&schema, &capabilities, query)?;

    assert_eq!(transformed.where_clauses[0].value, DbValue::Number(42));

    Ok(())
}

#[test]
fn transform_update_query_converts_timestamps_when_adapter_lacks_date_support(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let capabilities = AdapterCapabilities::new("legacy-sql").without_dates();
    let timestamp = OffsetDateTime::UNIX_EPOCH;
    let query = Update::new("session")
        .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
        .data("expires_at", DbValue::Timestamp(timestamp));

    let transformed = transform_update_query_with_capabilities(&schema, &capabilities, query)?;

    assert_eq!(
        transformed.data.get("expires_at"),
        Some(&DbValue::String(timestamp.to_string()))
    );

    Ok(())
}

#[test]
fn transform_create_query_keeps_json_native_when_adapter_supports_json() -> Result<(), OpenAuthError>
{
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_field("metadata", DbField::new("metadata", DbFieldType::Json)),
        ..AuthSchemaOptions::default()
    });
    let capabilities = AdapterCapabilities::new("postgres").with_json();
    let query = Create::new("user").data("metadata", DbValue::Json(json!({ "tier": "pro" })));

    let transformed = transform_create_query_with_capabilities(&schema, &capabilities, query)?;

    assert_eq!(
        transformed.data.get("metadata"),
        Some(&DbValue::Json(json!({ "tier": "pro" })))
    );

    Ok(())
}

#[test]
fn transform_create_query_stringifies_json_when_adapter_lacks_json_support(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_field("metadata", DbField::new("metadata", DbFieldType::Json)),
        ..AuthSchemaOptions::default()
    });
    let capabilities = AdapterCapabilities::new("legacy-sql");
    let query = Create::new("user").data("metadata", DbValue::Json(json!({ "tier": "pro" })));

    let transformed = transform_create_query_with_capabilities(&schema, &capabilities, query)?;

    assert_eq!(
        transformed.data.get("metadata"),
        Some(&DbValue::String("{\"tier\":\"pro\"}".to_owned()))
    );

    Ok(())
}

#[test]
fn transform_create_query_stringifies_arrays_when_adapter_lacks_array_support(
) -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_field("roles", DbField::new("roles", DbFieldType::StringArray)),
        ..AuthSchemaOptions::default()
    });
    let capabilities = AdapterCapabilities::new("legacy-sql");
    let query = Create::new("user").data("roles", DbValue::StringArray(vec!["admin".to_owned()]));

    let transformed = transform_create_query_with_capabilities(&schema, &capabilities, query)?;

    assert_eq!(
        transformed.data.get("roles"),
        Some(&DbValue::String("[\"admin\"]".to_owned()))
    );

    Ok(())
}

#[test]
fn resolve_join_options_maps_forward_foreign_key() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let joins = [("account".to_owned(), JoinOption::enabled())]
        .into_iter()
        .collect();

    let resolved = resolve_join_options(&schema, "user", joins, Vec::new(), 100)?;
    let account_join =
        resolved
            .joins
            .get("accounts")
            .ok_or_else(|| OpenAuthError::JoinForeignKeyNotFound {
                base_model: "user".to_owned(),
                join_model: "account".to_owned(),
            })?;

    assert_eq!(account_join.on.from, "id");
    assert_eq!(account_join.on.to, "user_id");
    assert_eq!(account_join.limit, Some(100));
    assert_eq!(account_join.relation, JoinRelation::OneToMany);

    Ok(())
}

#[test]
fn resolve_join_options_maps_reverse_foreign_key_as_one_to_one() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions::default());
    let joins = [("user".to_owned(), JoinOption::enabled())]
        .into_iter()
        .collect();

    let resolved = resolve_join_options(&schema, "account", joins, Vec::new(), 100)?;
    let user_join =
        resolved
            .joins
            .get("users")
            .ok_or_else(|| OpenAuthError::JoinForeignKeyNotFound {
                base_model: "account".to_owned(),
                join_model: "user".to_owned(),
            })?;

    assert_eq!(user_join.on.from, "user_id");
    assert_eq!(user_join.on.to, "id");
    assert_eq!(user_join.limit, Some(1));
    assert_eq!(user_join.relation, JoinRelation::OneToOne);

    Ok(())
}

#[test]
fn resolve_join_options_adds_required_select_field() -> Result<(), OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        account: TableOptions::default().with_field_name("user_id", "owner_id"),
        ..AuthSchemaOptions::default()
    });
    let joins = [("user".to_owned(), JoinOption::enabled())]
        .into_iter()
        .collect();

    let resolved = resolve_join_options(&schema, "account", joins, vec!["id".to_owned()], 100)?;

    assert_eq!(
        resolved.select,
        vec!["id".to_owned(), "owner_id".to_owned()]
    );

    Ok(())
}

#[test]
fn resolve_join_options_returns_typed_error_without_foreign_key() {
    let schema = auth_schema(AuthSchemaOptions::default());
    let joins = [("verification".to_owned(), JoinOption::enabled())]
        .into_iter()
        .collect();

    assert_eq!(
        resolve_join_options(&schema, "user", joins, Vec::new(), 100),
        Err(OpenAuthError::JoinForeignKeyNotFound {
            base_model: "user".to_owned(),
            join_model: "verification".to_owned()
        })
    );
}
