use openauth_core::context::create_auth_context;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::siwe::{siwe, SiweSchemaOptions};
use std::sync::Arc;

use super::{nonce, options, router, verify, WALLET};

#[test]
fn siwe_plugin_adds_wallet_address_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![siwe(options())?],
        ..OpenAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("walletAddress")
        .ok_or("walletAddress schema missing")?;
    assert_eq!(table.name, "wallet_addresses");
    assert!(table.field("userId").is_some());
    assert!(table.field("address").is_some());
    assert!(table.field("chainId").is_some());
    assert!(table.field("isPrimary").is_some());
    assert!(table.field("createdAt").is_some());
    Ok(())
}

#[test]
fn siwe_schema_options_override_table_and_field_names() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = options();
    opts = opts.schema(
        SiweSchemaOptions::new()
            .table_name("wallet_address")
            .field_name("userId", "user_id")
            .field_name("chainId", "chain_id")
            .field_name("isPrimary", "is_primary")
            .field_name("createdAt", "created_at"),
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![siwe(opts)?],
        ..OpenAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("walletAddress")
        .ok_or("walletAddress schema missing")?;
    assert_eq!(table.name, "wallet_address");
    assert_eq!(
        table.field("userId").map(|field| field.name.as_str()),
        Some("user_id")
    );
    assert_eq!(
        table.field("chainId").map(|field| field.name.as_str()),
        Some("chain_id")
    );
    assert_eq!(
        table.field("isPrimary").map(|field| field.name.as_str()),
        Some("is_primary")
    );
    assert_eq!(
        table.field("createdAt").map(|field| field.name.as_str()),
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
                .field_name("userId", "user_id")
                .field_name("address", "wallet_address")
                .field_name("chainId", "chain_id")
                .field_name("isPrimary", "is_primary")
                .field_name("createdAt", "created_at"),
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
    assert_eq!(adapter.len("walletAddress").await, 1);
    Ok(())
}
