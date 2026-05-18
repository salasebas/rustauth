use std::fs;
use std::path::{Path, PathBuf};

use openauth_core::db::{DbAdapter, DbSchema, SchemaMigrationPlan, SchemaMigrationWarning};
use openauth_core::error::OpenAuthError;
use openauth_sqlx::{MySqlAdapter, PostgresAdapter, SqliteAdapter};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::CliConfig;
use crate::schema::{dialect_from_provider, dialect_name, full_schema_plan, target_schema};

#[derive(Debug, thiserror::Error)]
pub enum DbCliError {
    #[error("database provider is not configured")]
    MissingProvider,
    #[error("database URL environment variable {0} is not set")]
    MissingDatabaseUrl(String),
    #[error("unsupported database provider `{0}`")]
    UnsupportedProvider(String),
    #[error("migration has non-executable warnings; fix schema mismatches before applying")]
    UnsafeMigration,
    #[error("A migration for this plan already exists: {0}")]
    DuplicateMigration(String),
    #[error("database error: {0}")]
    OpenAuth(#[from] OpenAuthError),
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
        let database_url = database_url(config)?;
        match provider.as_str() {
            "sqlite" | "sqlite3" => {
                ensure_sqlite_database(&database_url)?;
                SqliteAdapter::connect_with_schema(&database_url, schema.clone())
                    .await?
                    .plan_migrations(&schema)
                    .await?
            }
            "postgres" | "postgresql" | "pg" => {
                PostgresAdapter::connect_with_schema(&database_url, schema.clone())
                    .await?
                    .plan_migrations(&schema)
                    .await?
            }
            "mysql" => {
                MySqlAdapter::connect_with_schema(&database_url, schema.clone())
                    .await?
                    .plan_migrations(&schema)
                    .await?
            }
            _ => return Err(DbCliError::UnsupportedProvider(provider)),
        }
    };

    Ok(PlannedMigration {
        schema,
        plan,
        provider,
    })
}

pub async fn migrate(config: &CliConfig) -> Result<PlannedMigration, DbCliError> {
    let planned = plan(config, false).await?;
    if !planned.plan.warnings.is_empty() {
        return Err(DbCliError::UnsafeMigration);
    }
    let database_url = database_url(config)?;
    match planned.provider.as_str() {
        "sqlite" | "sqlite3" => {
            ensure_sqlite_database(&database_url)?;
            let adapter =
                SqliteAdapter::connect_with_schema(&database_url, planned.schema.clone()).await?;
            adapter.run_migrations(&planned.schema).await?;
        }
        "postgres" | "postgresql" | "pg" => {
            let adapter =
                PostgresAdapter::connect_with_schema(&database_url, planned.schema.clone()).await?;
            adapter.run_migrations(&planned.schema).await?;
        }
        "mysql" => {
            let adapter =
                MySqlAdapter::connect_with_schema(&database_url, planned.schema.clone()).await?;
            adapter.run_migrations(&planned.schema).await?;
        }
        _ => return Err(DbCliError::UnsupportedProvider(planned.provider.clone())),
    }
    Ok(planned)
}

pub fn migration_sql(config: &CliConfig, planned: &PlannedMigration) -> Result<String, DbCliError> {
    let dialect = dialect_from_provider(&planned.provider)
        .ok_or_else(|| DbCliError::UnsupportedProvider(planned.provider.clone()))?;
    let generated_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let schema_hash = schema_hash(&planned.schema)?;
    let plan_hash = plan_hash(&planned.plan);
    Ok(format!(
        "-- OpenAuth migration\n-- dialect: {}\n-- generated_at: {}\n-- schema_hash: {}\n-- plan_hash: {}\n-- config_base_path: {}\n\n{}",
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
    if planned.plan.is_empty() {
        return Ok(PathBuf::new());
    }
    let dir = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(&config.database.migrations_dir));
    let hash = plan_hash(&planned.plan);
    if let Some(existing) = find_existing_plan_hash(&dir, &hash)? {
        return Err(DbCliError::DuplicateMigration(
            existing.display().to_string(),
        ));
    }
    fs::create_dir_all(&dir).map_err(|source| DbCliError::CreateDir {
        path: dir.clone(),
        source,
    })?;
    let path = dir.join(format!(
        "{}_{}_{}.sql",
        filename_timestamp(),
        normalized_provider(&planned.provider),
        hash
    ));
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
        .map_err(|error| OpenAuthError::Adapter(format!("failed to serialize schema: {error}")))?;
    Ok(short_hash(&payload))
}

pub fn plan_hash(plan: &SchemaMigrationPlan) -> String {
    short_hash(plan.compile().as_bytes())
}

pub fn database_url(config: &CliConfig) -> Result<String, DbCliError> {
    std::env::var(&config.database.url_env)
        .map_err(|_| DbCliError::MissingDatabaseUrl(config.database.url_env.clone()))
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
