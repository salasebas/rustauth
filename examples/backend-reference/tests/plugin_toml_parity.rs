//! Ensures `[plugins].enabled` in `rustauth.toml` matches runtime plugin ids in Rust.

use std::path::PathBuf;

use rustauth_cli::config::CliConfig;
use rustauth_example_backend_reference::auth::options::enabled_plugin_ids;

fn load_reference_rustauth_toml() -> CliConfig {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rustauth.toml");
    CliConfig::load(&path).expect("load rustauth.toml")
}

#[test]
fn rustauth_toml_plugin_ids_match_enabled_plugin_ids() {
    let config = load_reference_rustauth_toml();
    let mut toml_ids = config.plugins.enabled;
    toml_ids.sort();

    let mut rust_ids = enabled_plugin_ids()
        .iter()
        .map(|id| (*id).to_owned())
        .collect::<Vec<_>>();
    rust_ids.sort();

    assert_eq!(
        toml_ids, rust_ids,
        "rustauth.toml [plugins].enabled must match ENABLED_PLUGIN_IDS in src/auth/plugins.rs"
    );

    assert!(
        !toml_ids.iter().any(|id| id == "access"),
        "access is a helper library, not an HTTP plugin — exclude it from migration lists"
    );
}
