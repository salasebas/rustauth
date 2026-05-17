use std::sync::Arc;

use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::api_key::{api_key, API_KEY_MODEL};

#[test]
fn api_key_schema_uses_plural_table_and_snake_case_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![api_key()],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter,
    )?;

    assert_eq!(context.db_schema.table_name(API_KEY_MODEL)?, "api_keys");
    for (logical, physical) in [
        ("config_id", "config_id"),
        ("reference_id", "reference_id"),
        ("refill_interval", "refill_interval"),
        ("refill_amount", "refill_amount"),
        ("last_refill_at", "last_refill_at"),
        ("rate_limit_enabled", "rate_limit_enabled"),
        ("rate_limit_time_window", "rate_limit_time_window"),
        ("rate_limit_max", "rate_limit_max"),
        ("request_count", "request_count"),
        ("last_request", "last_request"),
        ("expires_at", "expires_at"),
        ("created_at", "created_at"),
        ("updated_at", "updated_at"),
    ] {
        assert_eq!(
            context.db_schema.field_name(API_KEY_MODEL, logical)?,
            physical
        );
    }
    assert!(context.db_schema.field(API_KEY_MODEL, "config_id")?.index);
    assert!(
        context
            .db_schema
            .field(API_KEY_MODEL, "reference_id")?
            .index
    );
    assert!(context.db_schema.field(API_KEY_MODEL, "key")?.index);

    Ok(())
}
