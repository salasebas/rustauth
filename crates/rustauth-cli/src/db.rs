use std::fs;
use std::path::{Path, PathBuf};

use rustauth_core::db::{DbAdapter, DbSchema, SchemaMigrationPlan, SchemaMigrationWarning};
use rustauth_core::error::RustAuthError;
#[cfg(feature = "deadpool-postgres")]
use rustauth_deadpool_postgres::DeadpoolPostgresAdapter;
#[cfg(feature = "diesel")]
use rustauth_diesel::{DieselMysqlAdapter, DieselPostgresAdapter};
#[cfg(feature = "sqlx")]
use rustauth_sqlx::{MySqlAdapter, PostgresAdapter, SqliteAdapter};
#[cfg(feature = "tokio-postgres")]
use rustauth_tokio_postgres::TokioPostgresAdapter;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::CliConfig;
use crate::plugins::plugin_migrations_for_config;
use crate::schema::{dialect_from_provider, dialect_name, full_schema_plan, target_schema};

pub fn is_cli_migration_adapter(adapter: &str) -> bool {
    match adapter {
        "sqlx" if cfg!(feature = "sqlx") => true,
        "tokio-postgres" if cfg!(feature = "tokio-postgres") => true,
        "deadpool-postgres" if cfg!(feature = "deadpool-postgres") => true,
        "diesel" if cfg!(feature = "diesel") => true,
        _ => false,
    }
}

pub fn is_known_cli_migration_adapter(adapter: &str) -> bool {
    matches!(
        adapter,
        "sqlx" | "tokio-postgres" | "deadpool-postgres" | "diesel"
    )
}

fn is_adapter_feature_disabled(adapter: &str) -> bool {
    is_known_cli_migration_adapter(adapter) && !is_cli_migration_adapter(adapter)
}

pub fn cli_migration_adapter_names() -> Vec<&'static str> {
    let mut adapters = Vec::new();
    if cfg!(feature = "sqlx") {
        adapters.push("sqlx");
    }
    if cfg!(feature = "tokio-postgres") {
        adapters.push("tokio-postgres");
    }
    if cfg!(feature = "deadpool-postgres") {
        adapters.push("deadpool-postgres");
    }
    if cfg!(feature = "diesel") {
        adapters.push("diesel");
    }
    adapters
}

fn is_postgres_provider(provider: &str) -> bool {
    matches!(provider, "postgres" | "postgresql" | "pg")
}

fn is_mysql_provider(provider: &str) -> bool {
    provider == "mysql"
}

#[derive(Debug, thiserror::Error)]
pub enum DbCliError {
    #[error("database provider is not configured")]
    MissingProvider,
    #[error("database URL environment variable {0} is not set; add it to .env/.env.local next to the project or config file, or export it before running this command")]
    MissingDatabaseUrl(String),
    #[error(
        "unsupported database adapter `{adapter}`; {support}",
        adapter = .0,
        support = unsupported_adapter_support_suffix()
    )]
    UnsupportedAdapter(String),
    #[error(
        "database adapter `{0}` is not enabled in this CLI build; rebuild with the matching \
         Cargo feature ({1})"
    )]
    AdapterFeatureDisabled(String, String),
    #[error("unsupported database provider `{0}`")]
    UnsupportedProvider(String),
    #[error("migration has non-executable warnings; fix schema mismatches before applying")]
    UnsafeMigration,
    #[error("A migration for this plan already exists: {0}")]
    DuplicateMigration(String),
    #[error("database error: {0}")]
    RustAuth(#[from] RustAuthError),
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to create {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to format timestamp: {0}")]
    TimeFormat(#[from] time::error::Format),
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanSummary {
    pub provider: String,
    pub tables_to_create: usize,
    pub columns_to_add: usize,
    pub indexes_to_create: usize,
    pub warnings: Vec<SchemaMigrationWarning>,
    pub statements: usize,
    pub plan_hash: String,
}

#[derive(Debug, Clone)]
pub struct PlannedMigration {
    pub schema: DbSchema,
    pub plan: SchemaMigrationPlan,
    pub provider: String,
}

impl PlannedMigration {
    pub fn summary(&self) -> PlanSummary {
        PlanSummary {
            provider: self.provider.clone(),
            tables_to_create: self.plan.to_be_created.len(),
            columns_to_add: self.plan.to_be_added.len(),
            indexes_to_create: self.plan.indexes_to_be_created.len(),
            warnings: self.plan.warnings.clone(),
            statements: self.plan.statements.len(),
            plan_hash: plan_hash(&self.plan),
        }
    }
}

pub async fn plan(config: &CliConfig, from_empty: bool) -> Result<PlannedMigration, DbCliError> {
    plan_with_base(config, from_empty, None).await
}

pub async fn plan_with_base(
    config: &CliConfig,
    from_empty: bool,
    cwd: Option<&Path>,
) -> Result<PlannedMigration, DbCliError> {
    validate_cli_migration_adapter(config)?;
    let schema = target_schema(config)?;
    let provider = config
        .database
        .provider
        .clone()
        .ok_or(DbCliError::MissingProvider)?;

    let plan = if from_empty {
        let dialect = dialect_from_provider(&provider)
            .ok_or_else(|| DbCliError::UnsupportedProvider(provider.clone()))?;
        full_schema_plan(dialect, &schema)?
    } else {
        let database_url = database_url_with_base(config, cwd)?;
        match config.database.adapter.as_str() {
            #[cfg(feature = "sqlx")]
            "sqlx" => plan_with_sqlx(&provider, &database_url, &schema).await?,
            #[cfg(feature = "tokio-postgres")]
            "tokio-postgres" => {
                if !is_postgres_provider(&provider) {
                    return Err(DbCliError::UnsupportedProvider(provider));
                }
                TokioPostgresAdapter::connect_with_schema(&database_url, schema.clone())
                    .await?
                    .plan_migrations(&schema)
                    .await?
            }
            #[cfg(feature = "deadpool-postgres")]
            "deadpool-postgres" => {
                if !is_postgres_provider(&provider) {
                    return Err(DbCliError::UnsupportedProvider(provider));
                }
                DeadpoolPostgresAdapter::builder()
                    .database_url(database_url)
                    .schema(schema.clone())
                    .connect()
                    .await?
                    .plan_migrations(&schema)
                    .await?
            }
            #[cfg(feature = "diesel")]
            "diesel" => plan_with_diesel(&provider, &database_url, &schema).await?,
            adapter => return Err(adapter_dispatch_error(adapter)),
        }
    };

    Ok(PlannedMigration {
        schema,
        plan,
        provider,
    })
}

pub async fn migrate(config: &CliConfig) -> Result<PlannedMigration, DbCliError> {
    migrate_with_base(config, None).await
}

pub async fn migrate_with_base(
    config: &CliConfig,
    cwd: Option<&Path>,
) -> Result<PlannedMigration, DbCliError> {
    let planned = plan_with_base(config, false, cwd).await?;
    if !planned.plan.warnings.is_empty() {
        return Err(DbCliError::UnsafeMigration);
    }
    let database_url = database_url_with_base(config, cwd)?;
    let plugin_migrations = plugin_migrations_for_config(&config.plugins.enabled)?;
    match config.database.adapter.as_str() {
        #[cfg(feature = "sqlx")]
        "sqlx" => {
            run_migrations_with_sqlx(
                &planned.provider,
                &database_url,
                &planned.schema,
                &plugin_migrations,
            )
            .await?;
        }
        #[cfg(feature = "tokio-postgres")]
        "tokio-postgres" => {
            let adapter =
                TokioPostgresAdapter::connect_with_schema(&database_url, planned.schema.clone())
                    .await?;
            adapter.run_migrations(&planned.schema).await?;
            adapter.run_plugin_migrations(&plugin_migrations).await?;
        }
        #[cfg(feature = "deadpool-postgres")]
        "deadpool-postgres" => {
            let adapter = DeadpoolPostgresAdapter::builder()
                .database_url(database_url)
                .schema(planned.schema.clone())
                .connect()
                .await?;
            adapter.run_migrations(&planned.schema).await?;
            adapter.run_plugin_migrations(&plugin_migrations).await?;
        }
        #[cfg(feature = "diesel")]
        "diesel" => {
            run_migrations_with_diesel(
                &planned.provider,
                &database_url,
                &planned.schema,
                &plugin_migrations,
            )
            .await?;
        }
        adapter => return Err(adapter_dispatch_error(adapter)),
    }
    Ok(planned)
}

#[cfg(feature = "sqlx")]
async fn plan_with_sqlx(
    provider: &str,
    database_url: &str,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, DbCliError> {
    match provider {
        "sqlite" | "sqlite3" => {
            ensure_sqlite_database(database_url)?;
            SqliteAdapter::connect_with_schema(database_url, schema.clone())
                .await?
                .plan_migrations(schema)
                .await
                .map_err(Into::into)
        }
        "postgres" | "postgresql" | "pg" => {
            PostgresAdapter::connect_with_schema(database_url, schema.clone())
                .await?
                .plan_migrations(schema)
                .await
                .map_err(Into::into)
        }
        "mysql" => MySqlAdapter::connect_with_schema(database_url, schema.clone())
            .await?
            .plan_migrations(schema)
            .await
            .map_err(Into::into),
        other => Err(DbCliError::UnsupportedProvider(other.to_owned())),
    }
}

#[cfg(feature = "sqlx")]
async fn run_migrations_with_sqlx(
    provider: &str,
    database_url: &str,
    schema: &DbSchema,
    plugin_migrations: &[rustauth_core::plugin::PluginMigration],
) -> Result<(), DbCliError> {
    match provider {
        "sqlite" | "sqlite3" => {
            ensure_sqlite_database(database_url)?;
            let adapter = SqliteAdapter::connect_with_schema(database_url, schema.clone()).await?;
            adapter.run_migrations(schema).await?;
            adapter.run_plugin_migrations(plugin_migrations).await?;
        }
        "postgres" | "postgresql" | "pg" => {
            let adapter =
                PostgresAdapter::connect_with_schema(database_url, schema.clone()).await?;
            adapter.run_migrations(schema).await?;
            adapter.run_plugin_migrations(plugin_migrations).await?;
        }
        "mysql" => {
            let adapter = MySqlAdapter::connect_with_schema(database_url, schema.clone()).await?;
            adapter.run_migrations(schema).await?;
            adapter.run_plugin_migrations(plugin_migrations).await?;
        }
        other => return Err(DbCliError::UnsupportedProvider(other.to_owned())),
    }
    Ok(())
}

#[cfg(feature = "diesel")]
async fn plan_with_diesel(
    provider: &str,
    database_url: &str,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, DbCliError> {
    match provider {
        "postgres" | "postgresql" | "pg" => {
            DieselPostgresAdapter::connect_with_schema(database_url, schema.clone())
                .await?
                .plan_migrations(schema)
                .await
                .map_err(Into::into)
        }
        "mysql" => DieselMysqlAdapter::connect_with_schema(database_url, schema.clone())
            .await?
            .plan_migrations(schema)
            .await
            .map_err(Into::into),
        "sqlite" | "sqlite3" => Err(DbCliError::UnsupportedProvider(provider.to_owned())),
        other => Err(DbCliError::UnsupportedProvider(other.to_owned())),
    }
}

#[cfg(feature = "diesel")]
async fn run_migrations_with_diesel(
    provider: &str,
    database_url: &str,
    schema: &DbSchema,
    plugin_migrations: &[rustauth_core::plugin::PluginMigration],
) -> Result<(), DbCliError> {
    match provider {
        "postgres" | "postgresql" | "pg" => {
            let adapter =
                DieselPostgresAdapter::connect_with_schema(database_url, schema.clone()).await?;
            adapter.run_migrations(schema).await?;
            adapter.run_plugin_migrations(plugin_migrations).await?;
        }
        "mysql" => {
            let adapter =
                DieselMysqlAdapter::connect_with_schema(database_url, schema.clone()).await?;
            adapter.run_migrations(schema).await?;
            adapter.run_plugin_migrations(plugin_migrations).await?;
        }
        "sqlite" | "sqlite3" => return Err(DbCliError::UnsupportedProvider(provider.to_owned())),
        other => return Err(DbCliError::UnsupportedProvider(other.to_owned())),
    }
    Ok(())
}

pub fn migration_sql(config: &CliConfig, planned: &PlannedMigration) -> Result<String, DbCliError> {
    let dialect = dialect_from_provider(&planned.provider)
        .ok_or_else(|| DbCliError::UnsupportedProvider(planned.provider.clone()))?;
    let generated_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let schema_hash = schema_hash(&planned.schema)?;
    let plan_hash = plan_hash(&planned.plan);
    Ok(format!(
        "-- RustAuth migration\n-- dialect: {}\n-- generated_at: {}\n-- schema_hash: {}\n-- plan_hash: {}\n-- config_base_path: {}\n\n{}",
        dialect_name(dialect),
        generated_at,
        schema_hash,
        plan_hash,
        config.project.base_path,
        planned.plan.compile()
    ))
}

pub fn write_migration(
    config: &CliConfig,
    planned: &PlannedMigration,
    output: Option<&Path>,
    force: bool,
) -> Result<PathBuf, DbCliError> {
    write_migration_output(
        config,
        planned,
        output
            .map(|path| MigrationOutput::Directory(path.to_path_buf()))
            .unwrap_or(MigrationOutput::Default),
        force,
    )
}

pub enum MigrationOutput {
    Default,
    Directory(PathBuf),
    File(PathBuf),
}

pub fn write_migration_output(
    config: &CliConfig,
    planned: &PlannedMigration,
    output: MigrationOutput,
    force: bool,
) -> Result<PathBuf, DbCliError> {
    if planned.plan.is_empty() {
        return Ok(PathBuf::new());
    }
    let (dir, explicit_file) = match output {
        MigrationOutput::Default => (PathBuf::from(&config.database.migrations_dir), None),
        MigrationOutput::Directory(dir) => (dir, None),
        MigrationOutput::File(path) => (
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
            Some(path),
        ),
    };
    let hash = plan_hash(&planned.plan);
    if !force {
        if let Some(existing) = find_existing_plan_hash(&dir, &hash)? {
            return Err(DbCliError::DuplicateMigration(
                existing.display().to_string(),
            ));
        }
    }
    fs::create_dir_all(&dir).map_err(|source| DbCliError::CreateDir {
        path: dir.clone(),
        source,
    })?;
    let path = explicit_file.unwrap_or_else(|| {
        dir.join(format!(
            "{}_{}_{}.sql",
            filename_timestamp(),
            normalized_provider(&planned.provider),
            hash
        ))
    });
    if path.exists() && !force {
        return Err(DbCliError::DuplicateMigration(path.display().to_string()));
    }
    let sql = migration_sql(config, planned)?;
    fs::write(&path, sql).map_err(|source| DbCliError::Write {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

pub fn schema_hash(schema: &DbSchema) -> Result<String, DbCliError> {
    let payload = serde_json::to_vec(schema)
        .map_err(|error| RustAuthError::Adapter(format!("failed to serialize schema: {error}")))?;
    Ok(short_hash(&payload))
}

pub fn plan_hash(plan: &SchemaMigrationPlan) -> String {
    short_hash(plan.compile().as_bytes())
}

pub fn database_url(config: &CliConfig) -> Result<String, DbCliError> {
    database_url_with_base(config, None)
}

pub fn database_url_with_base(
    config: &CliConfig,
    cwd: Option<&Path>,
) -> Result<String, DbCliError> {
    std::env::var(&config.database.url_env)
        .map(|url| normalize_database_url(config.database.provider.as_deref(), &url, cwd))
        .map_err(|_| DbCliError::MissingDatabaseUrl(config.database.url_env.clone()))
}

pub fn supports_sql_migrations(config: &CliConfig) -> bool {
    if !is_cli_migration_adapter(&config.database.adapter) {
        return false;
    }
    match config.database.adapter.as_str() {
        "sqlx" if cfg!(feature = "sqlx") => config
            .database
            .provider
            .as_deref()
            .is_some_and(|provider| dialect_from_provider(provider).is_some()),
        "tokio-postgres" if cfg!(feature = "tokio-postgres") => config
            .database
            .provider
            .as_deref()
            .is_some_and(is_postgres_provider),
        "deadpool-postgres" if cfg!(feature = "deadpool-postgres") => config
            .database
            .provider
            .as_deref()
            .is_some_and(is_postgres_provider),
        "diesel" if cfg!(feature = "diesel") => {
            config.database.provider.as_deref().is_some_and(|provider| {
                is_postgres_provider(provider) || is_mysql_provider(provider)
            })
        }
        _ => false,
    }
}

/// Adapters that are valid in the ecosystem but not driven by `rustauth db migrate`.
///
/// For these we print guidance and exit successfully (Better Auth parity for Prisma/Drizzle).
pub fn unsupported_adapter_exits_successfully(adapter: &str) -> bool {
    matches!(
        adapter,
        "prisma" | "drizzle" | "memory" | "mongodb" | "kysely"
    )
}

pub fn unsupported_adapter_guidance(adapter: &str, command: &str) -> String {
    match adapter {
        "prisma" => format!(
            "The {command} command applies RustAuth SQL migrations through the sqlx adapter. \
             With Prisma configured, run `rustauth db generate` to write `.sql` files, then apply \
             them with `prisma migrate` or `prisma db push`."
        ),
        "drizzle" => format!(
            "The {command} command applies RustAuth SQL migrations through the sqlx adapter. \
             With Drizzle configured, run `rustauth db generate` to write `.sql` files, then apply \
             them with your Drizzle migration workflow."
        ),
        "kysely" => format!(
            "The {command} command uses the sqlx adapter in rustauth.toml. \
             Set `database.adapter = \"sqlx\"` and configure `database.provider`, or run \
             `rustauth db generate` and apply the SQL with your existing Kysely tooling."
        ),
        "memory" => format!(
            "The {command} command does not apply migrations for the in-memory adapter. \
             Use `database.adapter = \"sqlx\"` with a real provider for CLI migrations, or \
             `rustauth schema print` to inspect the target schema."
        ),
        "mongodb" => format!(
            "The {command} command does not support MongoDB. \
             Use a SQL provider with {}",
            enabled_adapter_guidance()
        ),
        other => format!(
            "Unsupported database adapter `{other}` for {command}. \
             RustAuth CLI migrations require {}",
            enabled_adapter_guidance()
        ),
    }
}

fn validate_cli_migration_adapter(config: &CliConfig) -> Result<(), DbCliError> {
    let adapter = config.database.adapter.as_str();
    if is_adapter_feature_disabled(adapter) {
        return Err(DbCliError::AdapterFeatureDisabled(
            adapter.to_owned(),
            adapter_cargo_feature(adapter).to_owned(),
        ));
    }
    if !is_cli_migration_adapter(adapter) {
        return Err(DbCliError::UnsupportedAdapter(
            config.database.adapter.clone(),
        ));
    }
    Ok(())
}

fn adapter_dispatch_error(adapter: &str) -> DbCliError {
    if is_adapter_feature_disabled(adapter) {
        DbCliError::AdapterFeatureDisabled(
            adapter.to_owned(),
            adapter_cargo_feature(adapter).to_owned(),
        )
    } else {
        DbCliError::UnsupportedAdapter(adapter.to_owned())
    }
}

fn adapter_cargo_feature(adapter: &str) -> &'static str {
    match adapter {
        "sqlx" => "sqlx",
        "tokio-postgres" => "tokio-postgres",
        "deadpool-postgres" => "deadpool-postgres",
        "diesel" => "diesel",
        _ => "unknown",
    }
}

fn unsupported_adapter_support_suffix() -> String {
    format!("CLI migrations support {}", enabled_adapter_guidance())
}

fn enabled_adapter_guidance() -> String {
    let mut parts = Vec::new();
    if cfg!(feature = "sqlx") {
        parts.push("`database.adapter = \"sqlx\"` (sqlite, postgres, mysql)".to_owned());
    }
    if cfg!(feature = "tokio-postgres") {
        parts.push("`database.adapter = \"tokio-postgres\"` (postgres only)".to_owned());
    }
    if cfg!(feature = "deadpool-postgres") {
        parts.push("`database.adapter = \"deadpool-postgres\"` (postgres only)".to_owned());
    }
    if cfg!(feature = "diesel") {
        parts.push("`database.adapter = \"diesel\"` (postgres, mysql)".to_owned());
    }
    if parts.is_empty() {
        "no database migration adapters in this CLI build".to_owned()
    } else {
        parts.join(", ")
    }
}

fn normalize_database_url(provider: Option<&str>, url: &str, cwd: Option<&Path>) -> String {
    if !matches!(provider, Some("sqlite" | "sqlite3")) {
        return url.to_owned();
    }
    let Some(cwd) = cwd else {
        return url.to_owned();
    };
    let Some(path) = sqlite_path(url) else {
        return url.to_owned();
    };
    if path.as_os_str().is_empty() || path.is_absolute() {
        return url.to_owned();
    }
    format!("sqlite://{}", cwd.join(path).display())
}

fn short_hash(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex::encode(&digest[..8])
}

fn find_existing_plan_hash(dir: &Path, hash: &str) -> Result<Option<PathBuf>, DbCliError> {
    if !dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(dir).map_err(|source| DbCliError::Read {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| DbCliError::Read {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("sql") {
            continue;
        }
        let content = fs::read_to_string(&path).map_err(|source| DbCliError::Read {
            path: path.clone(),
            source,
        })?;
        if content.contains(&format!("plan_hash: {hash}")) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn filename_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn normalized_provider(provider: &str) -> &str {
    match provider {
        "postgresql" | "pg" => "postgres",
        "sqlite3" => "sqlite",
        other => other,
    }
}

fn ensure_sqlite_database(database_url: &str) -> Result<(), DbCliError> {
    let Some(path) = sqlite_path(database_url) else {
        return Ok(());
    };
    if path.as_os_str().is_empty() || path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| DbCliError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::File::create(&path)
        .map(|_| ())
        .map_err(|source| DbCliError::Write { path, source })
}

fn sqlite_path(database_url: &str) -> Option<PathBuf> {
    if database_url == "sqlite::memory:" || database_url == "sqlite://:memory:" {
        return None;
    }
    database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "diesel")]
    fn diesel_is_known_cli_migration_adapter_when_feature_enabled() {
        assert!(is_known_cli_migration_adapter("diesel"));
        assert!(is_cli_migration_adapter("diesel"));
        assert!(cli_migration_adapter_names().contains(&"diesel"));
    }

    #[test]
    #[cfg(not(feature = "diesel"))]
    fn diesel_is_known_but_disabled_without_feature() {
        assert!(is_known_cli_migration_adapter("diesel"));
        assert!(!is_cli_migration_adapter("diesel"));
        assert!(!cli_migration_adapter_names().contains(&"diesel"));
    }
}
