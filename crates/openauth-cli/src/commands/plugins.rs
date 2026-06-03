use std::fs;

use crate::app::{AppContext, AppError, PluginChangeArgs, PluginListArgs};
use crate::config::CliConfig;
use crate::db;
use crate::output::print_json;
use crate::plugins::{is_official_plugin, official_plugins, rust_snippet};
use crate::prompt::confirm;

pub fn list(args: PluginListArgs) -> Result<(), AppError> {
    let plugins = official_plugins();
    if args.json {
        print_json(&plugins)?;
    } else {
        for plugin in plugins {
            let schema = if plugin.schema_supported {
                "schema"
            } else {
                "no schema"
            };
            println!("{} ({schema})", plugin.id);
        }
    }
    Ok(())
}

pub async fn add(context: &AppContext, args: PluginChangeArgs) -> Result<(), AppError> {
    if !is_official_plugin(&args.plugin) {
        return Err(AppError::Message(format!(
            "`{}` is not an official OpenAuth plugin.",
            args.plugin
        )));
    }
    let _ = context.load_config()?;
    let path = context.config_path();
    let source = fs::read_to_string(path).map_err(|source| AppError::Io {
        context: format!("failed to read {}", path.display()),
        source,
    })?;
    let updated = CliConfig::add_plugin_to_document(&source, &args.plugin)?;
    if !confirm(
        &format!("Add `{}` to {}?", args.plugin, path.display()),
        args.yes,
    )? {
        return Err(AppError::Message("Plugin update aborted.".to_owned()));
    }
    fs::write(path, updated).map_err(|source| AppError::Io {
        context: format!("failed to write {}", path.display()),
        source,
    })?;
    println!("Added plugin `{}` to {}.", args.plugin, path.display());
    if let Some(snippet) = rust_snippet(&args.plugin) {
        println!("Rust snippet: {snippet}");
    }
    let config = context.load_config()?;
    match db::plan_with_base(&config, false, Some(context.cwd())).await {
        Ok(plan) if !plan.plan.is_empty() => {
            println!("This plugin changes the database schema.");
            println!("Run `openauth db generate` or `openauth db migrate`.");
        }
        Ok(_) => {}
        Err(db::DbCliError::UnsupportedAdapter(_))
        | Err(db::DbCliError::UnsupportedProvider(_)) => {
            println!("Database impact check skipped for non-SQL configuration.");
        }
        Err(error) => {
            println!("Database impact could not be checked: {error}");
        }
    }
    Ok(())
}

pub fn remove(context: &AppContext, args: PluginChangeArgs) -> Result<(), AppError> {
    let _ = context.load_config()?;
    let path = context.config_path();
    let source = fs::read_to_string(path).map_err(|source| AppError::Io {
        context: format!("failed to read {}", path.display()),
        source,
    })?;
    let updated = CliConfig::remove_plugin_from_document(&source, &args.plugin)?;
    if !confirm(
        &format!("Remove `{}` from {}?", args.plugin, path.display()),
        args.yes,
    )? {
        return Err(AppError::Message("Plugin update aborted.".to_owned()));
    }
    fs::write(path, updated).map_err(|source| AppError::Io {
        context: format!("failed to write {}", path.display()),
        source,
    })?;
    println!("Removed plugin `{}` from {}.", args.plugin, path.display());
    println!("OpenAuth does not generate destructive migrations in v1.");
    Ok(())
}
