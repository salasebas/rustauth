//! Ensures `rustauth db migrate` (via CLI schema planning) covers the reference stack.

use std::path::PathBuf;

use rustauth_cli::config::CliConfig;
use rustauth_cli::plugins::schema_context_for_config;
use rustauth_core::db::DbSchema;

use rustauth_example_backend_reference::auth::options::enabled_plugin_ids;
use rustauth_example_backend_reference::auth::schema::resolve_schema;

fn table_names(schema: &DbSchema) -> Vec<String> {
    let mut names = schema
        .tables()
        .map(|(logical_name, _)| logical_name.to_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn plugin_ids_from_rustauth_toml() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rustauth.toml");
    let config = CliConfig::load(&path).expect("load rustauth.toml");
    config.plugins.enabled
}

#[test]
fn cli_schema_includes_all_reference_tables_except_app_configured_fields() {
    let app_schema = resolve_schema().expect("reference schema");
    let plugin_ids = plugin_ids_from_rustauth_toml();
    let cli_schema = schema_context_for_config(&plugin_ids)
        .expect("cli schema context")
        .db_schema;

    let rust_plugin_ids = enabled_plugin_ids()
        .iter()
        .map(|id| (*id).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        plugin_ids, rust_plugin_ids,
        "cli_schema_parity assumes rustauth.toml matches ENABLED_PLUGIN_IDS; see plugin_toml_parity.rs"
    );

    let app_tables = table_names(&app_schema);
    let cli_tables = table_names(&cli_schema);

    for table in &app_tables {
        assert!(
            cli_tables.contains(table),
            "CLI schema missing table `{table}` present in reference app schema"
        );
    }

    assert!(
        app_schema.field("user", "locale").is_ok(),
        "reference configures additional-fields user.locale"
    );
    assert!(
        cli_schema.field("user", "locale").is_err(),
        "CLI cannot infer additional-fields columns from plugin id alone"
    );
}
