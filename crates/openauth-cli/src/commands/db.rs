use std::path::Path;

use crate::app::{AppContext, AppError, GenerateArgs, MigrateArgs, StatusArgs};
use crate::commands::db_support::{ensure_safe_to_apply, map_db_error};
use crate::db::{self, MigrationOutput};
use crate::output::print_json;
use crate::prompt::confirm;
use crate::schema::{dialect_from_provider, dialect_name};
use crate::telemetry;

pub async fn status(context: &AppContext, args: StatusArgs) -> Result<(), AppError> {
    let config = context.load_config()?;
    let planned = match db::plan_with_base(&config, false, Some(context.cwd())).await {
        Ok(planned) => planned,
        Err(error) => return map_db_error(&config, "status", error).await,
    };
    let summary = planned.summary();
    if args.json {
        print_json(&summary)?;
    } else {
        print_plan(&planned);
    }
    if args.check && !planned.plan.is_empty() {
        return Err(AppError::SilentExit { code: 1 });
    }
    Ok(())
}

pub async fn generate(context: &AppContext, args: GenerateArgs) -> Result<(), AppError> {
    let config = context.load_config()?;
    let planned = match db::plan_with_base(&config, args.from_empty, Some(context.cwd())).await {
        Ok(planned) => planned,
        Err(error) => return map_db_error(&config, "generate", error).await,
    };
    if planned.plan.is_empty() {
        println!("Schema is already up to date.");
        telemetry::publish_generate(&config, "no_changes").await;
        return Ok(());
    }
    print_plan(&planned);
    let output = migration_output(
        context,
        &config,
        args.output.as_deref(),
        args.output_dir.as_deref(),
    )?;
    let target = match &output {
        MigrationOutput::File(path) => path.display().to_string(),
        MigrationOutput::Directory(path) => path.display().to_string(),
        MigrationOutput::Default => config.database.migrations_dir.clone(),
    };
    if !confirm(
        &format!("Generate migration artifacts under {target}?"),
        args.yes,
    )? {
        println!("Schema generation aborted.");
        telemetry::publish_generate(&config, "aborted").await;
        return Err(AppError::SilentExit { code: 1 });
    }
    let path = db::write_migration_output(&config, &planned, output, args.force)?;
    println!("Generated migration: {}", path.display());
    if args.force {
        let mut extra = serde_json::Map::new();
        extra.insert("forced".to_owned(), serde_json::Value::Bool(true));
        telemetry::publish_generate_with_extra(&config, "overwritten", extra).await;
    } else {
        telemetry::publish_generate(&config, "generated").await;
    }
    Ok(())
}

pub async fn migrate(context: &AppContext, args: MigrateArgs) -> Result<(), AppError> {
    let config = context.load_config()?;
    let planned = match db::plan_with_base(&config, false, Some(context.cwd())).await {
        Ok(planned) => planned,
        Err(error) => return map_db_error(&config, "migrate", error).await,
    };
    if planned.plan.is_empty() {
        println!("No migrations needed.");
        telemetry::publish_migrate(&config, "no_changes").await;
        return Ok(());
    }
    print_plan(&planned);
    ensure_safe_to_apply(&planned)?;
    if args.dry_run {
        println!("Dry run complete; no changes were applied.");
        telemetry::publish_migrate(&config, "dry_run").await;
        return Ok(());
    }
    if !confirm("Apply these migrations?", args.yes)? {
        println!("Migration cancelled.");
        telemetry::publish_migrate(&config, "aborted").await;
        return Ok(());
    }
    db::migrate_with_base(&config, Some(context.cwd())).await?;
    println!("Migration completed successfully.");
    telemetry::publish_migrate(&config, "migrated").await;
    Ok(())
}

fn migration_output(
    context: &AppContext,
    config: &crate::config::CliConfig,
    output: Option<&Path>,
    output_dir: Option<&Path>,
) -> Result<MigrationOutput, AppError> {
    match (output, output_dir) {
        (Some(_), Some(_)) => Err(AppError::Message(
            "Use only one of --output or --output-dir.".to_owned(),
        )),
        (Some(path), None) => {
            let resolved = context.resolve_project_path(path);
            if resolved
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("sql")
            {
                Ok(MigrationOutput::File(resolved))
            } else {
                eprintln!(
                    "warning: --output without a .sql extension is treated as a directory; prefer --output-dir"
                );
                Ok(MigrationOutput::Directory(resolved))
            }
        }
        (None, Some(path)) => {
            let resolved = context.resolve_project_path(path);
            Ok(MigrationOutput::Directory(resolved))
        }
        (None, None) => Ok(MigrationOutput::Directory(
            context.cwd().join(&config.database.migrations_dir),
        )),
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
