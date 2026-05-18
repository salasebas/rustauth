use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use inquire::Confirm;
use openauth_core::db::sql::SqlDialect;
use serde::Serialize;

use crate::config::{CliConfig, ConfigError};
use crate::db::{self, DbCliError};
use crate::diagnostics::{doctor, DiagnosticReport, Severity};
use crate::plugins::{is_official_plugin, official_plugins, rust_snippet};
use crate::schema::{dialect_from_provider, dialect_name, full_schema_plan, target_schema};
use crate::secret::{assess_secret, generate_secret, SecretSeverity};
use crate::workspace;

#[derive(Debug, Parser)]
#[command(name = "openauth", version, about = "Command-line tools for OpenAuth.")]
pub struct Cli {
    #[arg(long, global = true, default_value = ".")]
    cwd: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Init(InitArgs),
    Doctor(DiagnosticArgs),
    Info(InfoArgs),
    Secret(SecretArgs),
    Db(DbArgs),
    Generate(GenerateArgs),
    Migrate(MigrateArgs),
    Schema(SchemaArgs),
    Plugins(PluginsArgs),
    Completions(CompletionsArgs),
}

#[derive(Debug, clap::Args)]
struct InitArgs {
    #[arg(long)]
    framework: Option<String>,
    #[arg(long)]
    adapter: Option<String>,
    #[arg(long)]
    database: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long, value_delimiter = ',')]
    plugins: Vec<String>,
    #[arg(short = 'y', long)]
    yes: bool,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, clap::Args)]
struct DiagnosticArgs {
    #[arg(long)]
    production: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    strict: bool,
}

#[derive(Debug, clap::Args)]
struct InfoArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct SecretArgs {
    #[arg(long, default_value_t = 32)]
    bytes: usize,
    #[arg(long)]
    check: Option<String>,
    #[arg(long)]
    check_env: Option<String>,
}

#[derive(Debug, clap::Args)]
struct DbArgs {
    #[command(subcommand)]
    command: DbCommands,
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    Status(StatusArgs),
    Generate(GenerateArgs),
    Migrate(MigrateArgs),
}

#[derive(Debug, clap::Args)]
struct StatusArgs {
    #[arg(long)]
    json: bool,
    #[arg(long)]
    check: bool,
}

#[derive(Debug, clap::Args)]
struct GenerateArgs {
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    from_empty: bool,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, clap::Args)]
struct MigrateArgs {
    #[arg(long)]
    dry_run: bool,
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Debug, clap::Args)]
struct SchemaArgs {
    #[command(subcommand)]
    command: SchemaCommands,
}

#[derive(Debug, Subcommand)]
enum SchemaCommands {
    Print(SchemaPrintArgs),
}

#[derive(Debug, clap::Args)]
struct SchemaPrintArgs {
    #[arg(long, value_enum, default_value_t = SchemaFormat::Sql)]
    format: SchemaFormat,
    #[arg(long, default_value = "sqlite")]
    dialect: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaFormat {
    Sql,
    Json,
}

#[derive(Debug, clap::Args)]
struct PluginsArgs {
    #[command(subcommand)]
    command: PluginsCommands,
}

#[derive(Debug, Subcommand)]
enum PluginsCommands {
    List(PluginListArgs),
    Add(PluginChangeArgs),
    Remove(PluginChangeArgs),
}

#[derive(Debug, clap::Args)]
struct PluginListArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct PluginChangeArgs {
    plugin: String,
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    shell: Shell,
}

pub fn run() -> i32 {
    run_from(std::env::args_os())
}

pub fn run_cargo() -> i32 {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if args
        .get(1)
        .and_then(|arg| arg.to_str())
        .is_some_and(is_cargo_subcommand_name)
    {
        args.remove(1);
    }
    run_from(args)
}

fn is_cargo_subcommand_name(value: &str) -> bool {
    matches!(
        value,
        "openauth" | "open-auth" | "better-auth" | "betterauth"
    )
}

pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => match execute(cli) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        Err(error) => {
            let _ = error.print();
            error.exit_code()
        }
    }
}

fn execute(cli: Cli) -> Result<(), AppError> {
    let runtime = tokio::runtime::Runtime::new().map_err(AppError::Runtime)?;
    runtime.block_on(async move { execute_async(cli).await })
}

async fn execute_async(cli: Cli) -> Result<(), AppError> {
    let cwd = absolute_cwd(&cli.cwd)?;
    match cli.command {
        Commands::Init(args) => init(&cwd, args),
        Commands::Doctor(args) => doctor_command(&cwd, args).await,
        Commands::Info(args) => info_command(&cwd, args).await,
        Commands::Secret(args) => secret_command(args),
        Commands::Db(args) => match args.command {
            DbCommands::Status(args) => db_status(&cwd, args).await,
            DbCommands::Generate(args) => db_generate(&cwd, args).await,
            DbCommands::Migrate(args) => db_migrate(&cwd, args).await,
        },
        Commands::Generate(args) => db_generate(&cwd, args).await,
        Commands::Migrate(args) => db_migrate(&cwd, args).await,
        Commands::Schema(args) => match args.command {
            SchemaCommands::Print(args) => schema_print(&cwd, args),
        },
        Commands::Plugins(args) => match args.command {
            PluginsCommands::List(args) => plugins_list(args),
            PluginsCommands::Add(args) => plugin_add(&cwd, args).await,
            PluginsCommands::Remove(args) => plugin_remove(&cwd, args),
        },
        Commands::Completions(args) => completions(args),
    }
}

fn init(cwd: &Path, args: InitArgs) -> Result<(), AppError> {
    let config_path = cwd.join("openauth.toml");
    if config_path.exists() && !args.force {
        return Err(AppError::Message(format!(
            "{} already exists. Use --force to overwrite it.",
            config_path.display()
        )));
    }

    let detected = workspace::inspect(cwd).ok();
    let framework = args
        .framework
        .or_else(|| {
            detected
                .as_ref()
                .and_then(|info| info.detected_frameworks.first())
                .map(|item| item.name.clone())
        })
        .unwrap_or_else(|| "axum".to_owned());
    let database = args.database.or_else(detect_provider_from_env).or_else(|| {
        detected.as_ref().and_then(|info| {
            if info
                .detected_databases
                .iter()
                .any(|item| item.name == "sqlx")
            {
                Some("sqlite".to_owned())
            } else {
                None
            }
        })
    });

    let config = CliConfig {
        project: crate::config::ProjectConfig {
            framework: Some(framework.clone()),
            base_url: args
                .base_url
                .unwrap_or_else(|| "http://localhost:3000/api/auth".to_owned()),
            ..crate::config::ProjectConfig::default()
        },
        database: crate::config::DatabaseConfig {
            adapter: args.adapter.unwrap_or_else(|| "sqlx".to_owned()),
            provider: database.or(Some("sqlite".to_owned())),
            ..crate::config::DatabaseConfig::default()
        },
        plugins: crate::config::PluginsConfig {
            enabled: normalize_plugins(args.plugins)?,
        },
        ..CliConfig::default()
    };

    if config_path.exists() && !confirm("Overwrite existing openauth.toml?", args.yes)? {
        return Err(AppError::Message("Initialization aborted.".to_owned()));
    }
    config.write(&config_path)?;
    update_env_example(cwd, &config)?;
    println!("Created openauth.toml");
    println!("Updated .env.example");
    if framework == "axum" {
        println!();
        println!("Axum integration snippet:");
        println!("let app = openauth_axum::router(auth)?;");
    }
    Ok(())
}

async fn doctor_command(cwd: &Path, args: DiagnosticArgs) -> Result<(), AppError> {
    let config = load_config(cwd)?;
    let report = doctor(cwd, &config, args.production).await;
    if args.json {
        print_json(&report)?;
    } else {
        print_report(&report);
    }
    if report.has_errors() || (args.strict && report.has_warnings()) {
        return Err(AppError::ExitOnly);
    }
    Ok(())
}

async fn info_command(cwd: &Path, args: InfoArgs) -> Result<(), AppError> {
    let config = load_config(cwd)?;
    let report = doctor(cwd, &config, false).await;
    if args.json {
        print_json(&report)?;
    } else {
        println!("OpenAuth info");
        println!("Rust: {}", report.rust);
        println!("Cargo: {}", report.cargo);
        if let Some(root) = report.workspace_root {
            println!("Workspace: {root}");
        }
        println!(
            "Framework: {}",
            config.project.framework.unwrap_or_default()
        );
        println!("Adapter: {}", config.database.adapter);
        println!(
            "Database provider: {}",
            config.database.provider.unwrap_or_default()
        );
        println!("Plugins: {}", config.plugins.enabled.join(", "));
    }
    Ok(())
}

fn secret_command(args: SecretArgs) -> Result<(), AppError> {
    let value = match (args.check, args.check_env) {
        (Some(value), None) => Some(value),
        (None, Some(env)) => Some(std::env::var(&env).unwrap_or_default()),
        (Some(_), Some(_)) => {
            return Err(AppError::Message(
                "Use only one of --check or --check-env.".to_owned(),
            ))
        }
        (None, None) => None,
    };
    let Some(secret) = value else {
        println!("{}", generate_secret(args.bytes));
        return Ok(());
    };

    let assessment = assess_secret(&secret, true);
    match assessment.severity {
        SecretSeverity::Ok => {
            println!("{}", assessment.message);
            Ok(())
        }
        SecretSeverity::Warning => {
            eprintln!("{}", assessment.message);
            Ok(())
        }
        SecretSeverity::Error => Err(AppError::Message(assessment.message)),
    }
}

async fn db_status(cwd: &Path, args: StatusArgs) -> Result<(), AppError> {
    let config = load_config(cwd)?;
    let planned = db::plan(&config, false).await?;
    let summary = planned.summary();
    if args.json {
        print_json(&summary)?;
    } else {
        print_plan(&planned);
    }
    if args.check && !planned.plan.is_empty() {
        return Err(AppError::ExitOnly);
    }
    Ok(())
}

async fn db_generate(cwd: &Path, args: GenerateArgs) -> Result<(), AppError> {
    let config = load_config(cwd)?;
    let planned = db::plan(&config, args.from_empty).await?;
    if planned.plan.is_empty() {
        println!("Schema is already up to date.");
        return Ok(());
    }
    let output = args
        .output
        .as_ref()
        .map(|path| resolve_project_path(cwd, path))
        .unwrap_or_else(|| cwd.join(&config.database.migrations_dir));
    let path = db::write_migration(&config, &planned, Some(&output), args.force)?;
    println!("Generated migration: {}", path.display());
    Ok(())
}

async fn db_migrate(cwd: &Path, args: MigrateArgs) -> Result<(), AppError> {
    let config = load_config(cwd)?;
    let planned = db::plan(&config, false).await?;
    if planned.plan.is_empty() {
        println!("No migrations needed.");
        return Ok(());
    }
    print_plan(&planned);
    if args.dry_run {
        println!("Dry run complete; no changes were applied.");
        return Ok(());
    }
    if !confirm("Apply these migrations?", args.yes)? {
        println!("Migration cancelled.");
        return Ok(());
    }
    db::migrate(&config).await?;
    println!("Migration completed successfully.");
    Ok(())
}

fn schema_print(cwd: &Path, args: SchemaPrintArgs) -> Result<(), AppError> {
    let config = load_config(cwd)?;
    let schema = target_schema(&config)?;
    match args.format {
        SchemaFormat::Json => print_json(&schema)?,
        SchemaFormat::Sql => {
            let dialect = dialect_from_provider(&args.dialect).ok_or_else(|| {
                AppError::Message(format!("unsupported dialect `{}`", args.dialect))
            })?;
            let plan = full_schema_plan(dialect, &schema)?;
            println!("{}", plan.compile());
        }
    }
    Ok(())
}

fn plugins_list(args: PluginListArgs) -> Result<(), AppError> {
    let plugins = official_plugins();
    if args.json {
        print_json(&plugins)?;
    } else {
        for plugin in plugins {
            let schema = if plugin.schema { "schema" } else { "no schema" };
            println!("{} ({schema})", plugin.id);
        }
    }
    Ok(())
}

async fn plugin_add(cwd: &Path, args: PluginChangeArgs) -> Result<(), AppError> {
    if !is_official_plugin(&args.plugin) {
        return Err(AppError::Message(format!(
            "`{}` is not an official OpenAuth plugin.",
            args.plugin
        )));
    }
    let path = cwd.join("openauth.toml");
    let source = fs::read_to_string(&path).map_err(|source| AppError::Io {
        context: format!("failed to read {}", path.display()),
        source,
    })?;
    let updated = CliConfig::add_plugin_to_document(&source, &args.plugin)?;
    if !confirm(
        &format!("Add `{}` to openauth.toml?", args.plugin),
        args.yes,
    )? {
        return Err(AppError::Message("Plugin update aborted.".to_owned()));
    }
    fs::write(&path, updated).map_err(|source| AppError::Io {
        context: format!("failed to write {}", path.display()),
        source,
    })?;
    println!("Added plugin `{}` to openauth.toml.", args.plugin);
    if let Some(snippet) = rust_snippet(&args.plugin) {
        println!("Rust snippet: {snippet}");
    }
    let config = load_config(cwd)?;
    match db::plan(&config, false).await {
        Ok(plan) if !plan.plan.is_empty() => {
            println!("This plugin changes the database schema.");
            println!("Run `openauth db generate` or `openauth db migrate`.");
        }
        Ok(_) => {}
        Err(error) => {
            println!("Database impact could not be checked: {error}");
        }
    }
    Ok(())
}

fn plugin_remove(cwd: &Path, args: PluginChangeArgs) -> Result<(), AppError> {
    let path = cwd.join("openauth.toml");
    let source = fs::read_to_string(&path).map_err(|source| AppError::Io {
        context: format!("failed to read {}", path.display()),
        source,
    })?;
    let updated = CliConfig::remove_plugin_from_document(&source, &args.plugin)?;
    if !confirm(
        &format!("Remove `{}` from openauth.toml?", args.plugin),
        args.yes,
    )? {
        return Err(AppError::Message("Plugin update aborted.".to_owned()));
    }
    fs::write(&path, updated).map_err(|source| AppError::Io {
        context: format!("failed to write {}", path.display()),
        source,
    })?;
    println!("Removed plugin `{}` from openauth.toml.", args.plugin);
    println!("OpenAuth does not generate destructive migrations in v1.");
    Ok(())
}

fn completions(args: CompletionsArgs) -> Result<(), AppError> {
    let mut command = Cli::command();
    let name = command.get_name().to_owned();
    clap_complete::generate(args.shell, &mut command, name, &mut io::stdout());
    Ok(())
}

fn load_config(cwd: &Path) -> Result<CliConfig, AppError> {
    let path = cwd.join("openauth.toml");
    CliConfig::load(&path).map_err(AppError::Config)
}

fn update_env_example(cwd: &Path, config: &CliConfig) -> Result<(), AppError> {
    let path = cwd.join(".env.example");
    let mut content = if path.exists() {
        fs::read_to_string(&path).map_err(|source| AppError::Io {
            context: format!("failed to read {}", path.display()),
            source,
        })?
    } else {
        String::new()
    };
    append_env_if_missing(
        &mut content,
        &config.security.secret_env,
        generate_secret(32),
    );
    append_env_if_missing(
        &mut content,
        &config.database.url_env,
        default_database_url(config),
    );
    fs::write(&path, content).map_err(|source| AppError::Io {
        context: format!("failed to write {}", path.display()),
        source,
    })
}

fn append_env_if_missing(content: &mut String, key: &str, value: impl AsRef<str>) {
    let prefix = format!("{key}=");
    if content.lines().any(|line| line.starts_with(&prefix)) {
        return;
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&prefix);
    content.push_str(value.as_ref());
    content.push('\n');
}

fn default_database_url(config: &CliConfig) -> &'static str {
    match config.database.provider.as_deref() {
        Some("postgres") | Some("postgresql") | Some("pg") => {
            "postgres://user:password@localhost:5432/openauth"
        }
        Some("mysql") => "mysql://user:password@localhost:3306/openauth",
        _ => "sqlite://openauth.sqlite",
    }
}

fn detect_provider_from_env() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok()?;
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        return Some("postgres".to_owned());
    }
    if url.starts_with("mysql://") {
        return Some("mysql".to_owned());
    }
    if url.starts_with("sqlite://") || url.ends_with(".sqlite") || url.ends_with(".db") {
        return Some("sqlite".to_owned());
    }
    None
}

fn normalize_plugins(plugins: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut normalized = Vec::new();
    for plugin in plugins {
        let plugin = plugin.trim();
        if plugin.is_empty() {
            continue;
        }
        if !is_official_plugin(plugin) {
            return Err(AppError::Message(format!(
                "`{plugin}` is not an official OpenAuth plugin."
            )));
        }
        if !normalized.iter().any(|existing| existing == plugin) {
            normalized.push(plugin.to_owned());
        }
    }
    Ok(normalized)
}

fn print_report(report: &DiagnosticReport) {
    println!("OpenAuth doctor");
    println!("Rust: {}", report.rust);
    println!("Cargo: {}", report.cargo);
    if let Some(root) = &report.workspace_root {
        println!("Workspace: {root}");
    }
    for finding in &report.findings {
        let label = match finding.severity {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        };
        println!("[{label}] {}: {}", finding.code, finding.message);
    }
}

fn print_plan(planned: &db::PlannedMigration) {
    let dialect = dialect_from_provider(&planned.provider)
        .map(dialect_name)
        .unwrap_or("unknown");
    println!("OpenAuth schema plan ({dialect})");
    println!("Tables to create: {}", planned.plan.to_be_created.len());
    for table in &planned.plan.to_be_created {
        println!("  - {}", table.table_name);
    }
    println!("Columns to add: {}", planned.plan.to_be_added.len());
    for column in &planned.plan.to_be_added {
        println!("  - {}.{}", column.table_name, column.column_name);
    }
    println!(
        "Indexes to create: {}",
        planned.plan.indexes_to_be_created.len()
    );
    for index in &planned.plan.indexes_to_be_created {
        println!("  - {}", index.index_name);
    }
    for warning in &planned.plan.warnings {
        println!("WARNING: {warning:?}");
    }
}

fn print_json<T>(value: &T) -> Result<(), AppError>
where
    T: Serialize,
{
    let rendered = serde_json::to_string_pretty(value)?;
    println!("{rendered}");
    Ok(())
}

fn confirm(message: &str, yes: bool) -> Result<bool, AppError> {
    if yes {
        return Ok(true);
    }
    Confirm::new(message)
        .with_default(false)
        .prompt()
        .map_err(|error| AppError::Message(format!("prompt failed: {error}")))
}

fn absolute_cwd(cwd: &Path) -> Result<PathBuf, AppError> {
    let path = if cwd.is_absolute() {
        cwd.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| AppError::Io {
                context: "failed to read current directory".to_owned(),
                source,
            })?
            .join(cwd)
    };
    if path.exists() {
        Ok(path)
    } else {
        Err(AppError::Message(format!(
            "The directory {} does not exist.",
            path.display()
        )))
    }
}

fn resolve_project_path(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Db(#[from] DbCliError),
    #[error(transparent)]
    OpenAuth(#[from] openauth_core::error::OpenAuthError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("failed to start async runtime: {0}")]
    Runtime(std::io::Error),
    #[error("{context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
    #[error("")]
    ExitOnly,
}

#[allow(dead_code)]
fn _dialect_for_lints(dialect: SqlDialect) -> &'static str {
    dialect_name(dialect)
}
