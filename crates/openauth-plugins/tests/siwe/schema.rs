use openauth_core::context::create_auth_context;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::siwe::{siwe_with, SiweSchemaOptions};
use std::sync::Arc;

use super::{nonce, options, router, verify, WALLET};

#[test]
fn siwe_plugin_adds_wallet_address_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![siwe_with(options())?],
        ..OpenAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("wallet_address")
        .ok_or("wallet_address schema missing")?;
    assert_eq!(table.name, "wallet_addresses");
    assert_eq!(
        table.field("user_id").map(|field| field.name.as_str()),
        Some("user_id")
    );
    assert_eq!(
        table.field("address").map(|field| field.name.as_str()),
        Some("address")
    );
    assert_eq!(
        table.field("chain_id").map(|field| field.name.as_str()),
        Some("chain_id")
    );
    assert_eq!(
        table.field("is_primary").map(|field| field.name.as_str()),
        Some("is_primary")
    );
    assert_eq!(
        table.field("created_at").map(|field| field.name.as_str()),
        Some("created_at")
    );
    Ok(())
}

#[test]
fn siwe_schema_options_override_table_and_field_names() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = options();
    opts = opts.schema(
        SiweSchemaOptions::new()
            .table_name("wallet_address")
            .field_name("user_id", "user_id")
            .field_name("chain_id", "chain_id")
            .field_name("is_primary", "is_primary")
            .field_name("created_at", "created_at"),
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![siwe_with(opts)?],
        ..OpenAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("wallet_address")
        .ok_or("wallet_address schema missing")?;
    assert_eq!(table.name, "wallet_address");
    assert_eq!(
        table.field("user_id").map(|field| field.name.as_str()),
        Some("user_id")
    );
    assert_eq!(
        table.field("chain_id").map(|field| field.name.as_str()),
        Some("chain_id")
    );
    assert_eq!(
        table.field("is_primary").map(|field| field.name.as_str()),
        Some("is_primary")
    );
    assert_eq!(
        table.field("created_at").map(|field| field.name.as_str()),
        Some("created_at")
    );
    Ok(())
}

#[tokio::test]
async fn custom_schema_configuration_still_allows_endpoint_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(
        adapter.clone(),
        options().schema(
            SiweSchemaOptions::new()
                .table_name("wallet_address")
                .field_name("user_id", "user_id")
                .field_name("address", "wallet_address")
                .field_name("chain_id", "chain_id")
                .field_name("is_primary", "is_primary")
                .field_name("created_at", "created_at"),
        ),
    )?;

    nonce(&router, WALLET, Some(1)).await?;
    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(adapter.len("wallet_address").await, 1);
    Ok(())
}
