use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::config::{CliConfig, ConfigError};
use crate::db::DbCliError;

#[derive(Debug, Parser)]
#[command(name = "openauth", version, about = "Command-line tools for OpenAuth.")]
pub struct Cli {
    #[arg(long, global = true, default_value = ".")]
    cwd: PathBuf,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
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
pub(crate) struct InitArgs {
    #[arg(long)]
    pub(crate) framework: Option<String>,
    #[arg(long)]
    pub(crate) adapter: Option<String>,
    #[arg(long)]
    pub(crate) database: Option<String>,
    #[arg(long)]
    pub(crate) base_url: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub(crate) plugins: Vec<String>,
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct DiagnosticArgs {
    #[arg(long)]
    pub(crate) production: bool,
    #[arg(long)]
    pub(crate) json: bool,
    #[arg(long)]
    pub(crate) strict: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct InfoArgs {
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct SecretArgs {
    #[arg(long, default_value_t = 32)]
    pub(crate) bytes: usize,
    #[arg(long)]
    pub(crate) check: Option<String>,
    #[arg(long)]
    pub(crate) check_env: Option<String>,
    #[arg(long)]
    pub(crate) env_line: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct DbArgs {
    #[command(subcommand)]
    pub(crate) command: DbCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DbCommands {
    Status(StatusArgs),
    Generate(GenerateArgs),
    Migrate(MigrateArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct StatusArgs {
    #[arg(long)]
    pub(crate) json: bool,
    #[arg(long)]
    pub(crate) check: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct GenerateArgs {
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    #[arg(long)]
    pub(crate) output_dir: Option<PathBuf>,
    #[arg(long)]
    pub(crate) from_empty: bool,
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct MigrateArgs {
    #[arg(long)]
    pub(crate) dry_run: bool,
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct SchemaArgs {
    #[command(subcommand)]
    pub(crate) command: SchemaCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SchemaCommands {
    Print(SchemaPrintArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct SchemaPrintArgs {
    #[arg(long, value_enum, default_value_t = SchemaFormat::Sql)]
    pub(crate) format: SchemaFormat,
    #[arg(long, default_value = "sqlite")]
    pub(crate) dialect: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum SchemaFormat {
    Sql,
    Json,
}

#[derive(Debug, clap::Args)]
pub(crate) struct PluginsArgs {
    #[command(subcommand)]
    pub(crate) command: PluginsCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PluginsCommands {
    List(PluginListArgs),
    Add(PluginChangeArgs),
    Remove(PluginChangeArgs),
}

#[derive(Debug, clap::Args)]
pub(crate) struct PluginListArgs {
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct PluginChangeArgs {
    pub(crate) plugin: String,
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,
}

#[derive(Debug, clap::Args)]
pub(crate) struct CompletionsArgs {
    pub(crate) shell: Shell,
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
            Err(AppError::SilentExit { code }) => code,
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
    let cwd = crate::paths::absolute_cwd(&cli.cwd)?;
    crate::env::load_project_env(&cwd)?;
    let context = AppContext {
        config_path: crate::paths::resolve_config_path(&cwd, cli.config.as_deref()),
        cwd,
    };
    match cli.command {
        Commands::Init(args) => crate::commands::init::run(&context, args),
        Commands::Doctor(args) => crate::commands::doctor::run(&context, args).await,
        Commands::Info(args) => crate::commands::info::run(&context, args).await,
        Commands::Secret(args) => crate::commands::secret::run(args),
        Commands::Db(args) => match args.command {
            DbCommands::Status(args) => crate::commands::db::status(&context, args).await,
            DbCommands::Generate(args) => crate::commands::db::generate(&context, args).await,
            DbCommands::Migrate(args) => crate::commands::db::migrate(&context, args).await,
        },
        Commands::Generate(args) => crate::commands::db::generate(&context, args).await,
        Commands::Migrate(args) => crate::commands::db::migrate(&context, args).await,
        Commands::Schema(args) => match args.command {
            SchemaCommands::Print(args) => crate::commands::schema::print(&context, args),
        },
        Commands::Plugins(args) => match args.command {
            PluginsCommands::List(args) => crate::commands::plugins::list(args),
            PluginsCommands::Add(args) => crate::commands::plugins::add(&context, args).await,
            PluginsCommands::Remove(args) => crate::commands::plugins::remove(&context, args),
        },
        Commands::Completions(args) => crate::commands::completions::run(args),
    }
}

pub(crate) struct AppContext {
    cwd: PathBuf,
    config_path: PathBuf,
}

impl AppContext {
    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub(crate) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(crate) fn load_config(&self) -> Result<CliConfig, AppError> {
        CliConfig::load(&self.config_path).map_err(|error| match error {
            ConfigError::Read { path, source }
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                AppError::Message(format!(
                    "No OpenAuth CLI config found at {}. Run `openauth init` or pass --config <path>.",
                    path.display()
                ))
            }
            other => AppError::Config(other),
        })
    }

    /// Loads the config when present, otherwise falls back to defaults.
    ///
    /// Returns the config plus a flag indicating whether it was loaded from
    /// disk. A missing `openauth.toml` is not an error so read-only commands
    /// can run in a fresh checkout, but parse failures still surface.
    pub(crate) fn load_config_or_default(&self) -> Result<(CliConfig, bool), AppError> {
        match CliConfig::load_optional(&self.config_path)? {
            Some(config) => Ok((config, true)),
            None => Ok((CliConfig::default(), false)),
        }
    }

    pub(crate) fn resolve_project_path(&self, path: &Path) -> PathBuf {
        crate::paths::resolve_project_path(&self.cwd, path)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
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
    #[error("command exited with status {code}")]
    SilentExit { code: i32 },
}
