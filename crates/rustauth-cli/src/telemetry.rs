use rustauth_core::options::RustAuthOptions;
use rustauth_core::plugin::AuthPlugin;
use rustauth_telemetry::{
    create_telemetry, get_telemetry_auth_config, TelemetryContext, TelemetryEvent,
};
use serde_json::{Map, Value};

use crate::config::CliConfig;

pub(crate) async fn publish_generate(config: &CliConfig, outcome: &'static str) {
    publish_cli_event(config, "cli_generate", outcome, Map::new()).await;
}

pub(crate) async fn publish_generate_with_extra(
    config: &CliConfig,
    outcome: &'static str,
    extra: Map<String, Value>,
) {
    publish_cli_event(config, "cli_generate", outcome, extra).await;
}

pub(crate) async fn publish_migrate(config: &CliConfig, outcome: &'static str) {
    publish_cli_event(config, "cli_migrate", outcome, Map::new()).await;
}

#[allow(dead_code)]
pub(crate) async fn publish_migrate_with_extra(
    config: &CliConfig,
    outcome: &'static str,
    extra: Map<String, Value>,
) {
    publish_cli_event(config, "cli_migrate", outcome, extra).await;
}

pub(crate) async fn publish_cli_event_for_command(
    config: &CliConfig,
    command: &'static str,
    outcome: &'static str,
    extra: Map<String, Value>,
) {
    let event_type = match command {
        "generate" => "cli_generate",
        "migrate" => "cli_migrate",
        _ => "cli_generate",
    };
    publish_cli_event(config, event_type, outcome, extra).await;
}

async fn publish_cli_event(
    config: &CliConfig,
    event_type: &'static str,
    outcome: &'static str,
    extra: Map<String, Value>,
) {
    let options = telemetry_options(config);
    let context = telemetry_context(config);
    let publisher = create_telemetry(&options, context.clone()).await;
    publisher
        .publish(TelemetryEvent {
            event_type: event_type.to_owned(),
            anonymous_id: None,
            payload: cli_payload(&options, &context, outcome, extra),
        })
        .await;
}

fn telemetry_options(config: &CliConfig) -> RustAuthOptions {
    let mut options = RustAuthOptions::new()
        .base_url(config.project.base_url.clone())
        .base_path(config.project.base_path.clone())
        .production(config.project.production);

    options.plugins = config
        .plugins
        .enabled
        .iter()
        .map(|id| AuthPlugin::new(id.clone()))
        .collect();
    options
}

fn telemetry_context(config: &CliConfig) -> TelemetryContext {
    TelemetryContext {
        adapter: config.database.adapter.clone(),
        database: config.database.provider.clone(),
        ..TelemetryContext::default()
    }
}

fn cli_payload(
    options: &RustAuthOptions,
    context: &TelemetryContext,
    outcome: &'static str,
    extra: Map<String, Value>,
) -> Value {
    let mut payload = Map::new();
    payload.insert("outcome".to_owned(), Value::String(outcome.to_owned()));
    payload.extend(extra);
    payload.insert(
        "config".to_owned(),
        get_telemetry_auth_config(options, context),
    );
    Value::Object(payload)
}
