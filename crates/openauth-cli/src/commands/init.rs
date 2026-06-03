use std::fs;

use crate::app::{AppContext, AppError, InitArgs};
use crate::config::{CliConfig, DatabaseConfig, PluginsConfig, ProjectConfig};
use crate::plugins::is_official_plugin;
use crate::prompt::confirm;
use crate::secret::generate_secret;
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
    sync_env_files(context, &config, args.seed_secrets)?;
    println!("Created openauth.toml");
    println!("Synced .env.example and .env (created .env when missing)");
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

fn sync_env_files(
    context: &AppContext,
    config: &CliConfig,
    seed_secrets: bool,
) -> Result<(), AppError> {
    let example_path = context.cwd().join(".env.example");
    let mut example = if example_path.exists() {
        fs::read_to_string(&example_path).map_err(|source| AppError::Io {
            context: format!("failed to read {}", example_path.display()),
            source,
        })?
    } else {
        String::new()
    };
    merge_env_template(&mut example, config);
    fs::write(&example_path, &example).map_err(|source| AppError::Io {
        context: format!("failed to write {}", example_path.display()),
        source,
    })?;

    let env_path = context.cwd().join(".env");
    if env_path.exists() {
        let mut env = fs::read_to_string(&env_path).map_err(|source| AppError::Io {
            context: format!("failed to read {}", env_path.display()),
            source,
        })?;
        merge_env_template(&mut env, config);
        fs::write(&env_path, env).map_err(|source| AppError::Io {
            context: format!("failed to write {}", env_path.display()),
            source,
        })?;
    } else {
        let mut seeded = example.clone();
        if seed_secrets {
            seed_secret_in_env(&mut seeded, config);
        }
        fs::write(&env_path, seeded).map_err(|source| AppError::Io {
            context: format!("failed to write {}", env_path.display()),
            source,
        })?;
    }
    Ok(())
}

fn merge_env_template(content: &mut String, config: &CliConfig) {
    append_env_if_missing(
        content,
        &config.security.secret_env,
        "<generate-with-openauth-secret>",
    );
    append_env_if_missing(
        content,
        &config.database.url_env,
        default_database_url(config),
    );
    if !content.contains("openauth.toml") {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content
            .push_str("# OpenAuth base URL is configured in openauth.toml ([project].base_url)\n");
    }
}

fn seed_secret_in_env(content: &mut String, config: &CliConfig) {
    let key = &config.security.secret_env;
    let secret = generate_secret(32);
    let prefix = format!("{key}=");
    let lines: Vec<_> = content.lines().collect();
    let mut rebuilt = String::new();
    let mut replaced = false;
    for line in lines {
        if line.starts_with(&prefix) {
            if !replaced {
                rebuilt.push_str(&prefix);
                rebuilt.push_str(&secret);
                rebuilt.push('\n');
                replaced = true;
            }
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push('\n');
    }
    if !replaced {
        if !rebuilt.is_empty() && !rebuilt.ends_with('\n') {
            rebuilt.push('\n');
        }
        rebuilt.push_str(&prefix);
        rebuilt.push_str(&secret);
        rebuilt.push('\n');
    }
    *content = rebuilt;
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
