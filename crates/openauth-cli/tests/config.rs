#![allow(clippy::expect_used)]

use openauth_cli::config::{CliConfig, DatabaseConfig, ProjectConfig};

#[test]
fn parses_default_config_contract() {
    let config: CliConfig = r#"
[project]
framework = "axum"
base_url = "http://localhost:3000/api/auth"
base_path = "/api/auth"
production = false

[database]
adapter = "sqlx"
provider = "sqlite"
url_env = "DATABASE_URL"
migrations_dir = "migrations/openauth"

[security]
secret_env = "OPENAUTH_SECRET"

[plugins]
enabled = ["two-factor"]
"#
    .parse()
    .expect("config should parse");

    assert_eq!(config.project.framework.as_deref(), Some("axum"));
    assert_eq!(config.database.provider.as_deref(), Some("sqlite"));
    assert_eq!(config.plugins.enabled, vec!["two-factor"]);
}

#[test]
fn writes_config_without_dropping_unknown_keys() {
    let source = r#"
[project]
framework = "axum"
custom = "keep"

[plugins]
enabled = ["username"]
"#;

    let updated = CliConfig::add_plugin_to_document(source, "two-factor")
        .expect("plugin update should succeed");

    assert!(updated.contains("custom = \"keep\""));
    assert!(updated.contains("\"username\""));
    assert!(updated.contains("\"two-factor\""));
}

#[test]
fn default_config_uses_stable_contract() {
    let config = CliConfig {
        project: ProjectConfig {
            framework: Some("axum".to_owned()),
            ..ProjectConfig::default()
        },
        database: DatabaseConfig {
            provider: Some("sqlite".to_owned()),
            ..DatabaseConfig::default()
        },
        ..CliConfig::default()
    };

    let rendered = config.to_toml_string().expect("config should render");

    assert!(rendered.contains("[project]"));
    assert!(rendered.contains("framework = \"axum\""));
    assert!(rendered.contains("[database]"));
    assert!(rendered.contains("migrations_dir = \"migrations/openauth\""));
}
