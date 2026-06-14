pub mod app;
pub(crate) mod commands;
pub mod config;
pub mod db;
pub mod diagnostics;
pub(crate) mod env;
pub(crate) mod output;
pub(crate) mod paths;
pub mod plugins;
pub(crate) mod prompt;
pub mod schema;
pub mod secret;
#[cfg(feature = "telemetry")]
pub(crate) mod telemetry;
#[cfg(not(feature = "telemetry"))]
pub(crate) mod telemetry {
    use crate::config::CliConfig;
    use serde_json::Map;

    pub(crate) async fn publish_generate(_: &CliConfig, _: &'static str) {}

    pub(crate) async fn publish_generate_with_extra(
        _: &CliConfig,
        _: &'static str,
        _: Map<String, serde_json::Value>,
    ) {
    }

    pub(crate) async fn publish_migrate(_: &CliConfig, _: &'static str) {}

    #[allow(dead_code)]
    pub(crate) async fn publish_migrate_with_extra(
        _: &CliConfig,
        _: &'static str,
        _: Map<String, serde_json::Value>,
    ) {
    }

    pub(crate) async fn publish_cli_event_for_command(
        _: &CliConfig,
        _: &'static str,
        _: &'static str,
        _: Map<String, serde_json::Value>,
    ) {
    }
}
pub mod workspace;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod manifest_tests {
    use cargo_metadata::MetadataCommand;

    /// OPE-144: `cargo run -p rustauth-cli` must resolve the canonical binary without `--bin`.
    #[test]
    fn default_run_is_rustauth() {
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest_path)
            .no_deps()
            .exec()
            .expect("read crate manifest");
        let package = metadata
            .packages
            .into_iter()
            .find(|pkg| pkg.name == "rustauth-cli")
            .expect("rustauth-cli package in manifest");

        assert_eq!(
            package.default_run.as_deref(),
            Some("rustauth"),
            "set default-run = \"rustauth\" so contributors can run `cargo run -p rustauth-cli`"
        );
    }
}
