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
pub(crate) mod telemetry;
pub mod workspace;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod manifest_tests {
    use cargo_metadata::MetadataCommand;

    /// OPE-144: `cargo run -p openauth-cli` must resolve the canonical binary without `--bin`.
    #[test]
    fn default_run_is_openauth() {
        let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(&manifest_path)
            .no_deps()
            .exec()
            .expect("read crate manifest");
        let package = metadata
            .packages
            .into_iter()
            .find(|pkg| pkg.name == "openauth-cli")
            .expect("openauth-cli package in manifest");

        assert_eq!(
            package.default_run.as_deref(),
            Some("openauth"),
            "set default-run = \"openauth\" so contributors can run `cargo run -p openauth-cli`"
        );
    }
}
