#![cfg(feature = "full")]
#![allow(clippy::expect_used)]

use rustauth_cli::config::CliConfig;
use rustauth_cli::plugins::supports_schema_planning;
use rustauth_plugins::{APP_CONFIGURED_SCHEMA_PLUGIN_IDS, NO_FIXED_SCHEMA_PLUGIN_IDS, PLUGIN_IDS};

const BACKEND_REFERENCE_RUSTAUTH_TOML: &str =
    include_str!("../../../examples/backend-reference/rustauth.toml");

fn backend_reference_enabled_plugins() -> Vec<String> {
    CliConfig::parse_str(BACKEND_REFERENCE_RUSTAUTH_TOML)
        .expect("backend-reference rustauth.toml")
        .plugins
        .enabled
}

fn is_exempt_from_cli_schema_registry(plugin_id: &str) -> bool {
    NO_FIXED_SCHEMA_PLUGIN_IDS.contains(&plugin_id)
        || APP_CONFIGURED_SCHEMA_PLUGIN_IDS.contains(&plugin_id)
}

fn is_known_backend_reference_plugin(plugin_id: &str) -> bool {
    PLUGIN_IDS.contains(&plugin_id)
        || matches!(
            plugin_id,
            "oauth-provider" | "passkey" | "scim" | "sso" | "stripe"
        )
        // Runtime id for have-i-been-pwned; upstream catalog uses `haveibeenpwned`.
        || plugin_id == "have-i-been-pwned"
}

#[test]
fn backend_reference_enabled_plugins_are_known() {
    for plugin_id in backend_reference_enabled_plugins() {
        assert!(
            is_known_backend_reference_plugin(&plugin_id),
            "unexpected plugin id in backend-reference rustauth.toml: {plugin_id}"
        );
    }
}

#[test]
fn backend_reference_fixed_schema_plugins_are_in_cli_registry() {
    let missing: Vec<_> = backend_reference_enabled_plugins()
        .iter()
        .filter(|plugin_id| !is_exempt_from_cli_schema_registry(plugin_id))
        .filter(|plugin_id| !supports_schema_planning(plugin_id))
        .cloned()
        .collect();

    assert!(
        missing.is_empty(),
        "schema-contributing plugins missing from CLI registry: {missing:?}"
    );
}

#[test]
fn backend_reference_schema_exemptions_are_documented() {
    let enabled = backend_reference_enabled_plugins();
    for plugin_id in NO_FIXED_SCHEMA_PLUGIN_IDS {
        if enabled.iter().any(|id| id == plugin_id) {
            assert!(
                !supports_schema_planning(plugin_id),
                "{plugin_id} is exempt and must stay out of the CLI schema registry"
            );
        }
    }
    for plugin_id in APP_CONFIGURED_SCHEMA_PLUGIN_IDS {
        if enabled.iter().any(|id| id == plugin_id) {
            assert!(
                !supports_schema_planning(plugin_id),
                "{plugin_id} is app-configured and must stay out of the CLI schema registry"
            );
        }
    }
}
