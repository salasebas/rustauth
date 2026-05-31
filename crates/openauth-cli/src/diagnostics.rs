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
    pub openauth_version: String,
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
            "Loaded OpenAuth CLI configuration from openauth.toml.",
        ));
    } else {
        findings.push(warn(
            "config.missing",
            "No openauth.toml found; using defaults. Run `openauth init` to create one.",
        ));
    }
    inspect_workspace(&mut findings, workspace.as_ref(), config);
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
        openauth_version: env!("CARGO_PKG_VERSION").to_owned(),
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
        serde_json::Value::String(config.database.adapter.clone()),
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
    if config.database.adapter == "sqlx" && !package_has_dependency(workspace, "openauth-sqlx") {
        findings.push(error(
            "database.adapter_mismatch",
            "Config uses the sqlx adapter, but openauth-sqlx was not detected in dependencies.",
        ));
    }
    if config.database.adapter != "sqlx"
        && config.database.provider.as_deref().is_some_and(|provider| {
            matches!(
                provider,
                "sqlite" | "sqlite3" | "postgres" | "postgresql" | "pg" | "mysql"
            )
        })
    {
        findings.push(warn(
            "database.adapter_provider_mismatch",
            "database.provider is SQL-compatible but database.adapter is not sqlx.",
        ));
    }
    if workspace.detected_databases.len() > 1 && config.database.provider.is_none() {
        findings.push(warn(
            "database.multiple_adapters",
            "Multiple database integrations were detected; configure database.provider explicitly.",
        ));
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
                    "Database schema has pending OpenAuth changes.",
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
