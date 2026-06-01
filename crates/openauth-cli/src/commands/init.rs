use std::fs;

use crate::app::{AppContext, AppError, InitArgs};
use crate::config::{CliConfig, DatabaseConfig, PluginsConfig, ProjectConfig};
use crate::plugins::is_official_plugin;
use crate::prompt::confirm;
use crate::workspace;

pub fn run(context: &AppContext, args: InitArgs) -> Result<(), AppError> {
    let config_path = context.config_path();
    if config_path.exists() && !args.force {
        return Err(AppError::Message(format!(
            "{} already exists. Use --force to overwrite it.",
            config_path.display()
        )));
    }

    let detected = workspace::inspect(context.cwd()).ok();
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
            info.detected_databases
                .iter()
                .any(|item| item.name == "sqlx")
                .then(|| "sqlite".to_owned())
        })
    });

    let config = CliConfig {
        project: ProjectConfig {
            framework: Some(framework.clone()),
            base_url: args
                .base_url
                .unwrap_or_else(|| "http://localhost:3000/api/auth".to_owned()),
            ..ProjectConfig::default()
        },
        database: DatabaseConfig {
            adapter: args.adapter.unwrap_or_else(|| "sqlx".to_owned()),
            provider: database.or(Some("sqlite".to_owned())),
            ..DatabaseConfig::default()
        },
        plugins: PluginsConfig {
            enabled: normalize_plugins(args.plugins)?,
        },
        ..CliConfig::default()
    };

    if config_path.exists() && !confirm("Overwrite existing openauth.toml?", args.yes)? {
        return Err(AppError::Message("Initialization aborted.".to_owned()));
    }
    config.write(config_path)?;
    update_env_example(context, &config)?;
    println!("Created openauth.toml");
    println!("Updated .env.example");
    if framework == "axum" {
        println!();
        println!("Axum integration snippet:");
        println!("use std::net::SocketAddr;");
        println!();
        println!("let app = openauth_axum::router(auth)?;");
        println!("let listener = tokio::net::TcpListener::bind(\"127.0.0.1:3000\").await?;");
        println!("// Serve with ConnectInfo so OpenAuth rate limiting sees the real client IP.");
        println!(
            "axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;"
        );
        println!("// Behind a proxy, configure trusted forwarding headers explicitly instead.");
    }
    Ok(())
}

fn update_env_example(context: &AppContext, config: &CliConfig) -> Result<(), AppError> {
    let path = context.cwd().join(".env.example");
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
        "<generate-with-openauth-secret>",
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
