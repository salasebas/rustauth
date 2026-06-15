use crate::app::AppError;
use crate::config::CliConfig;
use crate::db::{self, DbCliError};
use crate::telemetry;
use serde_json::Map;

pub(crate) async fn map_db_error(
    config: &CliConfig,
    command: &'static str,
    error: DbCliError,
) -> Result<(), AppError> {
    match &error {
        DbCliError::UnsupportedAdapter(adapter)
            if db::unsupported_adapter_exits_successfully(adapter) =>
        {
            eprintln!("{}", db::unsupported_adapter_guidance(adapter, command));
            telemetry::publish_cli_event_for_command(
                config,
                command,
                "unsupported_adapter",
                unsupported_adapter_payload(config),
            )
            .await;
            Err(AppError::SilentExit { code: 0 })
        }
        DbCliError::AdapterFeatureDisabled(_, _) => {
            telemetry::publish_cli_event_for_command(
                config,
                command,
                "unsupported_adapter",
                unsupported_adapter_payload(config),
            )
            .await;
            Err(error.into())
        }
        DbCliError::UnsupportedAdapter(_) => {
            telemetry::publish_cli_event_for_command(
                config,
                command,
                "unsupported_adapter",
                unsupported_adapter_payload(config),
            )
            .await;
            Err(error.into())
        }
        DbCliError::UnsupportedProvider(_) => {
            telemetry::publish_cli_event_for_command(
                config,
                command,
                "unsupported_database",
                unsupported_adapter_payload(config),
            )
            .await;
            Err(error.into())
        }
        _ => Err(error.into()),
    }
}

pub(crate) fn unsupported_adapter_payload(config: &CliConfig) -> Map<String, serde_json::Value> {
    let mut payload = Map::new();
    payload.insert(
        "adapter".to_owned(),
        serde_json::Value::String(config.database_adapter().unwrap_or_default().to_owned()),
    );
    if let Some(provider) = &config.database.provider {
        payload.insert(
            "database".to_owned(),
            serde_json::Value::String(provider.clone()),
        );
    }
    payload
}

pub(crate) fn ensure_safe_to_apply(planned: &db::PlannedMigration) -> Result<(), AppError> {
    if planned.plan.warnings.is_empty() {
        return Ok(());
    }
    for warning in &planned.plan.warnings {
        eprintln!("WARNING: {warning:?}");
    }
    Err(DbCliError::UnsafeMigration.into())
}
