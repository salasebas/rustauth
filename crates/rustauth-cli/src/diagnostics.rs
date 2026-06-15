use std::collections::BTreeMap;

use serde::Serialize;
use url::Url;

use crate::config::CliConfig;
use crate::db;
use crate::secret::{assess_secret, SecretSeverity};
use crate::workspace::{command_version, inspect, package_has_dependency, WorkspaceInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticReport {
    pub workspace_root: Option<String>,
    pub target_package: Option<String>,
    pub rustauth_version: String,
    pub rust: String,
    pub cargo: String,
    pub config: RedactedConfig,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct RedactedConfig {
    pub project: BTreeMap<String, serde_json::Value>,
    pub database: BTreeMap<String, serde_json::Value>,
    pub security: BTreeMap<String, serde_json::Value>,
    pub plugins: Vec<String>,
}

impl DiagnosticReport {
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    }

    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Warn)
    }
}

pub async fn doctor(
    cwd: &std::path::Path,
    config: &CliConfig,
    production_override: bool,
    config_loaded: bool,
) -> DiagnosticReport {
    let production = production_override || config.project.production;
    let workspace = inspect(cwd).ok();
    let mut findings = Vec::new();

    if config_loaded {
        findings.push(info(
            "config.loaded",
            "Loaded RustAuth CLI configuration from rustauth.toml.",
        ));
        if config.database_adapter().is_none() {
            findings.push(error(
                "database.adapter_missing",
                "database.adapter is required in rustauth.toml; set it explicitly \
                 (e.g. sqlx, diesel, tokio-postgres, deadpool-postgres).",
            ));
        }
        inspect_plugin_cli_features(&mut findings, config);
    } else {
        findings.push(warn(
            "config.missing",
            "No rustauth.toml found; using defaults. Run `rustauth init` to create one.",
        ));
    }
    inspect_workspace(&mut findings, workspace.as_ref(), config);
    inspect_integration_patterns(&mut findings, cwd);
    inspect_security(&mut findings, config, production);
    inspect_database(&mut findings, config, production).await;

    DiagnosticReport {
        workspace_root: workspace
            .as_ref()
            .map(|info| info.root.display().to_string()),
        target_package: workspace
            .as_ref()
            .and_then(|info| info.packages.first())
            .map(|package| package.name.clone()),
        rustauth_version: env!("CARGO_PKG_VERSION").to_owned(),
        rust: command_version("rustc").unwrap_or_else(|_| "not available".to_owned()),
        cargo: command_version("cargo").unwrap_or_else(|_| "not available".to_owned()),
        config: redact_config(config),
        findings,
    }
}

pub fn redact_config(config: &CliConfig) -> RedactedConfig {
    let mut project = BTreeMap::new();
    project.insert(
        "framework".to_owned(),
        serde_json::Value::String(config.project.framework.clone().unwrap_or_default()),
    );
    project.insert(
        "base_url".to_owned(),
        serde_json::Value::String(config.project.base_url.clone()),
    );
    project.insert(
        "base_path".to_owned(),
        serde_json::Value::String(config.project.base_path.clone()),
    );
    project.insert(
        "production".to_owned(),
        serde_json::Value::Bool(config.project.production),
    );

    let mut database = BTreeMap::new();
    database.insert(
        "adapter".to_owned(),
        serde_json::Value::String(config.database_adapter().unwrap_or_default().to_owned()),
    );
    database.insert(
        "provider".to_owned(),
        serde_json::Value::String(config.database.provider.clone().unwrap_or_default()),
    );
    database.insert(
        "normalized_provider".to_owned(),
        serde_json::Value::String(normalized_provider(config.database.provider.as_deref())),
    );
    database.insert(
        "migration_support".to_owned(),
        serde_json::Value::Bool(db::supports_sql_migrations(config)),
    );
    database.insert(
        "url_env".to_owned(),
        serde_json::Value::String(config.database.url_env.clone()),
    );
    database.insert(
        "database_url".to_owned(),
        serde_json::Value::String("[REDACTED]".to_owned()),
    );

    let mut security = BTreeMap::new();
    security.insert(
        "secret_env".to_owned(),
        serde_json::Value::String(config.security.secret_env.clone()),
    );
    security.insert(
        "secret".to_owned(),
        serde_json::Value::String("[REDACTED]".to_owned()),
    );

    RedactedConfig {
        project,
        database,
        security,
        plugins: config.plugins.enabled.clone(),
    }
}

fn inspect_plugin_cli_features(findings: &mut Vec<Finding>, config: &CliConfig) {
    for id in &config.plugins.enabled {
        if let Some(feature) = crate::plugins::required_cargo_feature(id) {
            if !crate::plugins::is_cargo_feature_enabled(feature) {
                findings.push(error(
                    "plugins.cli_feature_disabled",
                    &format!(
                        "Plugin `{id}` is enabled in rustauth.toml, but this rustauth CLI binary \
                         was compiled without the `{feature}` Cargo feature."
                    ),
                ));
            }
        }
        if !crate::plugins::supports_schema_planning(id)
            && !crate::plugins::is_schema_planning_exception(id)
        {
            findings.push(warn(
                "plugins.schema_unknown",
                &format!(
                    "Plugin `{id}` is enabled but the CLI cannot plan schema for it. \
                     App-configured plugins such as additional-fields need manual migration \
                     alignment — see docs/database-migrations.md."
                ),
            ));
        }
    }
}

fn inspect_adapter_dependency_alignment(
    findings: &mut Vec<Finding>,
    workspace: &WorkspaceInfo,
    config: &CliConfig,
) {
    match config.database_adapter() {
        Some("sqlx") => {
            if !cfg!(feature = "sqlx") {
                findings.push(cli_adapter_feature_disabled_finding("sqlx"));
            } else if !package_has_dependency(workspace, "rustauth-sqlx") {
                findings.push(adapter_dependency_mismatch_finding("sqlx", "rustauth-sqlx"));
            }
        }
        Some("tokio-postgres") => {
            if !cfg!(feature = "tokio-postgres") {
                findings.push(cli_adapter_feature_disabled_finding("tokio-postgres"));
            } else if !package_has_dependency(workspace, "rustauth-tokio-postgres") {
                findings.push(adapter_dependency_mismatch_finding(
                    "tokio-postgres",
                    "rustauth-tokio-postgres",
                ));
            }
        }
        Some("deadpool-postgres") => {
            if !cfg!(feature = "deadpool-postgres") {
                findings.push(cli_adapter_feature_disabled_finding("deadpool-postgres"));
            } else if !package_has_dependency(workspace, "rustauth-deadpool-postgres") {
                findings.push(adapter_dependency_mismatch_finding(
                    "deadpool-postgres",
                    "rustauth-deadpool-postgres",
                ));
            }
        }
        Some("diesel") => {
            if !cfg!(feature = "diesel") {
                findings.push(cli_adapter_feature_disabled_finding("diesel"));
            } else if !package_has_dependency(workspace, "rustauth-diesel") {
                findings.push(adapter_dependency_mismatch_finding(
                    "diesel",
                    "rustauth-diesel",
                ));
            }
        }
        _ => {}
    }
}

fn cli_adapter_feature_disabled_finding(adapter: &str) -> Finding {
    error(
        "database.cli_feature_disabled",
        &format!(
            "Config uses the {adapter} adapter, but this rustauth CLI binary was compiled \
             without the `{adapter}` Cargo feature."
        ),
    )
}

fn adapter_dependency_mismatch_finding(adapter: &str, crate_name: &str) -> Finding {
    error(
        "database.adapter_mismatch",
        &format!(
            "Config uses the {adapter} adapter, but {crate_name} was not detected in dependencies."
        ),
    )
}

fn inspect_workspace(
    findings: &mut Vec<Finding>,
    workspace: Option<&WorkspaceInfo>,
    config: &CliConfig,
) {
    let Some(workspace) = workspace else {
        findings.push(warn(
            "workspace.metadata",
            "Cargo metadata could not be loaded from this directory.",
        ));
        return;
    };
    findings.push(info(
        "workspace.root",
        &format!("Workspace root: {}", workspace.root.display()),
    ));
    for framework in &workspace.detected_frameworks {
        findings.push(info(
            "framework.detected",
            &format!("Detected framework: {}", framework.name),
        ));
    }
    inspect_adapter_dependency_alignment(findings, workspace, config);
    if !db::supports_sql_migrations(config)
        && config.database.provider.as_deref().is_some_and(|provider| {
            matches!(
                provider,
                "sqlite" | "sqlite3" | "postgres" | "postgresql" | "pg" | "mysql"
            )
        })
    {
        findings.push(warn(
            "database.adapter_provider_mismatch",
            "database.provider is SQL-compatible but database.adapter does not support CLI migrations.",
        ));
    }
    if workspace.detected_databases.len() > 1 && config.database.provider.is_none() {
        findings.push(warn(
            "database.multiple_adapters",
            "Multiple database integrations were detected; configure database.provider explicitly.",
        ));
    }
}

fn inspect_integration_patterns(findings: &mut Vec<Finding>, cwd: &std::path::Path) {
    let src = cwd.join("src");
    if !src.is_dir() {
        return;
    }
    let mut legacy_router = false;
    let mut double_nest = false;
    walk_rs_sources(&src, &mut |contents| {
        if contents.contains("rustauth_axum::router(") {
            legacy_router = true;
        }
        if (contents.contains(".mount_router(") || contents.contains(".mount_at_base_path("))
            && contents.contains(".nest(")
        {
            double_nest = true;
        }
    });
    if legacy_router {
        findings.push(warn(
            "integration.legacy_router",
            "Detected rustauth_axum::router(); prefer Arc<RustAuth> + mount_routes() + Router::nest.",
        ));
    }
    if double_nest {
        findings.push(warn(
            "integration.double_nest",
            "Detected mount_at_base_path() (or deprecated mount_router()) and .nest() in the same source tree; avoid nesting twice on the same prefix.",
        ));
    }
}

fn walk_rs_sources(dir: &std::path::Path, visit: &mut dyn FnMut(&str)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_sources(&path, visit);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                visit(&contents);
            }
        }
    }
}

fn inspect_security(findings: &mut Vec<Finding>, config: &CliConfig, production: bool) {
    let secret = std::env::var(&config.security.secret_env).unwrap_or_default();
    let assessment = assess_secret(&secret, production);
    match assessment.severity {
        SecretSeverity::Ok => findings.push(info("security.secret", &assessment.message)),
        SecretSeverity::Warning => findings.push(warn("security.secret", &assessment.message)),
        SecretSeverity::Error => findings.push(error("security.secret", &assessment.message)),
    }
    if production && !config.project.base_url.starts_with("https://") {
        findings.push(error(
            "security.base_url_https",
            "base_url must use HTTPS in production.",
        ));
    }
    if production && is_localhost_url(&config.project.base_url) {
        findings.push(warn(
            "security.localhost",
            "base_url points to localhost while production checks are enabled.",
        ));
    }
}

async fn inspect_database(findings: &mut Vec<Finding>, config: &CliConfig, production: bool) {
    if !db::supports_sql_migrations(config) {
        findings.push(warn(
            "database.migrations_unsupported",
            "CLI migration checks are skipped for this database adapter/provider.",
        ));
        return;
    }
    if production && std::env::var(&config.database.url_env).is_err() {
        findings.push(error(
            "database.url",
            &format!("{} is required in production.", config.database.url_env),
        ));
        return;
    }
    if std::env::var(&config.database.url_env).is_err() {
        findings.push(warn(
            "database.url",
            &format!(
                "{} is not set; database checks were skipped.",
                config.database.url_env
            ),
        ));
        return;
    }
    match db::plan(config, false).await {
        Ok(plan) => {
            if !plan.plan.warnings.is_empty() {
                findings.push(error(
                    "database.schema_type_mismatch",
                    "Database schema has type mismatches.",
                ));
            }
            if !plan.plan.is_empty() {
                findings.push(warn(
                    "database.pending_schema",
                    "Database schema has pending RustAuth changes.",
                ));
            } else {
                findings.push(info("database.schema", "Database schema is up to date."));
            }
        }
        Err(db_error) => findings.push(error("database.connection", &db_error.to_string())),
    }
}

fn normalized_provider(provider: Option<&str>) -> String {
    match provider {
        Some("postgresql" | "pg") => "postgres".to_owned(),
        Some("sqlite3") => "sqlite".to_owned(),
        Some(provider) => provider.to_owned(),
        None => String::new(),
    }
}

fn is_localhost_url(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "::1")
}

fn info(code: &str, message: &str) -> Finding {
    finding(Severity::Info, code, message)
}

fn warn(code: &str, message: &str) -> Finding {
    finding(Severity::Warn, code, message)
}

fn error(code: &str, message: &str) -> Finding {
    finding(Severity::Error, code, message)
}

fn finding(severity: Severity, code: &str, message: &str) -> Finding {
    Finding {
        severity,
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliConfig;

    fn config_with_plugins(ids: &[&str]) -> CliConfig {
        let mut config = CliConfig::default();
        config.plugins.enabled = ids.iter().map(|id| (*id).to_owned()).collect();
        config
    }

    fn finding_codes(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect()
    }

    #[test]
    fn magic_link_enabled_does_not_report_cli_feature_disabled() {
        let mut findings = Vec::new();
        inspect_plugin_cli_features(&mut findings, &config_with_plugins(&["magic-link"]));
        assert!(
            !finding_codes(&findings).contains(&"plugins.cli_feature_disabled"),
            "magic-link has no enterprise CLI feature requirement"
        );
    }

    #[cfg(feature = "passkey")]
    #[test]
    fn passkey_with_feature_enabled_does_not_report_cli_feature_disabled() {
        let mut findings = Vec::new();
        inspect_plugin_cli_features(&mut findings, &config_with_plugins(&["passkey"]));
        assert!(
            !finding_codes(&findings).contains(&"plugins.cli_feature_disabled"),
            "passkey should succeed when the passkey feature is enabled"
        );
    }

    #[cfg(not(feature = "passkey"))]
    #[test]
    fn passkey_without_feature_reports_cli_feature_disabled() {
        let mut findings = Vec::new();
        inspect_plugin_cli_features(&mut findings, &config_with_plugins(&["passkey"]));
        assert!(
            finding_codes(&findings).contains(&"plugins.cli_feature_disabled"),
            "passkey requires the passkey Cargo feature"
        );
    }
}
