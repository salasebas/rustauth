//! Telemetry collection compatible with Better Auth `@better-auth/telemetry` (v1.6.9).
//!
//! # Environment variables
//!
//! All telemetry-related variables use the **`OPENAUTH_*`** prefix:
//!
//! | Purpose | Variable |
//! |---------|----------|
//! | Master switch | `OPENAUTH_TELEMETRY` |
//! | Debug logging (prints JSON instead of POST) | `OPENAUTH_TELEMETRY_DEBUG` |
//! | Collector URL | `OPENAUTH_TELEMETRY_ENDPOINT` |
//!
//! ## Enablement precedence
//!
//! `OPENAUTH_TELEMETRY` is a master switch that takes precedence over
//! [`TelemetryOptions::enabled`](openauth_core::options::TelemetryOptions):
//!
//! - `OPENAUTH_TELEMETRY=false` (or `0`) is a hard opt-out: telemetry stays off
//!   even when application code sets `TelemetryOptions::enabled(true)`.
//! - `OPENAUTH_TELEMETRY=true` (or `1`) is an opt-in that enables telemetry on
//!   its own, regardless of the options value.
//! - When the variable is unset, [`TelemetryOptions`](openauth_core::options::TelemetryOptions)
//!   decides (disabled by default).
//!
//! Regardless of the switch, telemetry is also suppressed under tests (unless
//! [`TelemetryContext::skip_test_check`](crate::TelemetryContext) is set).
//!
//! Unless `OPENAUTH_TELEMETRY_ENDPOINT` is set **or** [`TelemetryContext::custom_track`](crate::TelemetryContext) is provided, the publisher is a no-op: nothing is sent over the network. The maintainer of OpenAuth does not receive telemetry by default; whoever deploys the app chooses the endpoint (their own collector, internal analytics, etc.) or wires `custom_track`.
//!
//! # Intentional gaps vs upstream
//!
//! - **Framework** detection is stubbed to Axum until HTTP stack sniffing exists.
//! - **Database** detection from manifests is not implemented (`None` unless overridden in tests).
//! - **`get_telemetry_auth_config`** emits Better Auth-shaped JSON; many branches are static defaults
//!   until matching fields exist on [`openauth_core::options::OpenAuthOptions`].
//! - **Runtime** is reported as `rust` (not Node/Bun/Deno).
//! - **System metrics** (CPU, memory, Docker, WSL, TTY) are mostly unset (`null`), matching the
//!   non-Node “edge” build of upstream telemetry.
//! - **HTTP**: JSON POST uses `reqwest` when the `http` feature is enabled (default).

mod auth_config;
mod detectors;
mod env;
mod project_id;
mod transport;
pub mod types;
mod utils;

pub use auth_config::get_telemetry_auth_config;
pub use types::{
    CustomTrackFn, DetectionInfo, RuntimeInfo, TelemetryContext, TelemetryEvent,
    TelemetryHttpError, TelemetryHttpTransport, TelemetryTestHooks,
};

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::options::OpenAuthOptions;
use serde_json::json;
use tokio::sync::Mutex;

use crate::project_id::resolve_project_id;
#[cfg(not(feature = "http"))]
use crate::transport::NoopTransport;
#[cfg(feature = "http")]
use crate::transport::ReqwestTelemetryTransport;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

type TrackFn =
    Arc<dyn Fn(TelemetryEvent) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Live telemetry handle ([`Self::publish`] is a no-op when telemetry is disabled).
#[derive(Clone)]
pub struct TelemetryPublisher {
    hard_noop: bool,
    enabled: bool,
    anonymous_id: Arc<Mutex<Option<String>>>,
    base_url: Option<String>,
    test_anonymous_id: Option<String>,
    track: TrackFn,
}

impl TelemetryPublisher {
    /// Never publishes (upstream behavior when no endpoint and no custom sink).
    pub fn noop() -> Self {
        Self {
            hard_noop: true,
            enabled: false,
            anonymous_id: Arc::new(Mutex::new(None)),
            base_url: None,
            test_anonymous_id: None,
            track: Arc::new(|_| Box::pin(async move {})),
        }
    }

    pub async fn publish(&self, event: TelemetryEvent) {
        if self.hard_noop || !self.enabled {
            return;
        }
        let mut guard = self.anonymous_id.lock().await;
        if guard.is_none() {
            let id = self
                .test_anonymous_id
                .clone()
                .unwrap_or_else(|| resolve_project_id(self.base_url.as_deref()));
            *guard = Some(id);
        }
        let anonymous_id = guard.clone().unwrap_or_default();
        drop(guard);
        let TelemetryEvent {
            event_type,
            payload,
            ..
        } = event;
        let full = TelemetryEvent {
            event_type,
            anonymous_id: Some(anonymous_id),
            payload,
        };
        (self.track)(full).await;
    }
}

fn resolve_transport(context: &TelemetryContext) -> Arc<dyn TelemetryHttpTransport> {
    if let Some(client) = &context.http_transport {
        return client.clone();
    }
    #[cfg(feature = "http")]
    {
        Arc::new(ReqwestTelemetryTransport::default())
    }
    #[cfg(not(feature = "http"))]
    {
        return Arc::new(NoopTransport);
    }
}

async fn is_enabled(options: &OpenAuthOptions, context: &TelemetryContext) -> bool {
    // `OPENAUTH_TELEMETRY` is the master switch and takes precedence over
    // `TelemetryOptions`: an explicit opt-out (`false` / `0`) forces telemetry
    // off even when options enable it. When unset, options decide; an explicit
    // opt-in (`true` / `1`) enables telemetry on its own.
    let env_setting = crate::env::telemetry_env_setting();
    if env_setting == Some(false) {
        return false;
    }
    let opt_on = options.telemetry.enabled.unwrap_or(false);
    let allow_under_test = context.skip_test_check || !crate::env::is_test();
    (env_setting == Some(true) || opt_on) && allow_under_test
}

fn debug_enabled(options: &OpenAuthOptions) -> bool {
    options.telemetry.debug || crate::env::telemetry_debug_env()
}

fn build_track_fn(
    context: &TelemetryContext,
    endpoint: Option<String>,
    debug_mode: bool,
    transport: Arc<dyn TelemetryHttpTransport>,
) -> TrackFn {
    let custom = context.custom_track.clone();
    Arc::new(move |event: TelemetryEvent| {
        let custom = custom.clone();
        let endpoint = endpoint.clone();
        let transport = transport.clone();
        Box::pin(async move {
            if let Some(cb) = custom {
                let _ = tokio::spawn(async move { cb(event).await }).await;
                return;
            }
            let Some(url) = endpoint else {
                return;
            };
            let Ok(body) = event.to_json_value() else {
                return;
            };
            if debug_mode {
                eprintln!(
                    "telemetry event {}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
                return;
            }
            let _ = transport.post_json(&url, &body).await;
        })
    })
}

fn runtime_for(context: &TelemetryContext) -> RuntimeInfo {
    context
        .test_hooks
        .as_ref()
        .and_then(|h| h.runtime.clone())
        .unwrap_or_else(detectors::detect_runtime)
}

fn database_for(context: &TelemetryContext) -> Option<DetectionInfo> {
    context
        .test_hooks
        .as_ref()
        .and_then(|h| h.database.clone())
        .unwrap_or_else(detectors::detect_database)
}

fn framework_for(context: &TelemetryContext) -> Option<DetectionInfo> {
    context
        .test_hooks
        .as_ref()
        .and_then(|h| h.framework.clone())
        .unwrap_or_else(detectors::detect_framework)
}

fn environment_for(context: &TelemetryContext) -> String {
    context
        .test_hooks
        .as_ref()
        .and_then(|h| h.environment.clone())
        .unwrap_or_else(detectors::detect_environment)
}

fn system_info_for(context: &TelemetryContext) -> serde_json::Value {
    context
        .test_hooks
        .as_ref()
        .and_then(|h| h.system_info.clone())
        .unwrap_or_else(detectors::detect_system_info)
}

fn package_manager_for(context: &TelemetryContext) -> Option<DetectionInfo> {
    context
        .test_hooks
        .as_ref()
        .and_then(|h| h.package_manager.clone())
        .unwrap_or_else(detectors::detect_package_manager)
}

/// Creates a telemetry publisher (possibly a hard no-op when neither endpoint nor custom track exist).
pub async fn create_telemetry(
    options: &OpenAuthOptions,
    context: TelemetryContext,
) -> TelemetryPublisher {
    let endpoint = crate::env::telemetry_endpoint();
    if endpoint.is_none() && context.custom_track.is_none() {
        return TelemetryPublisher::noop();
    }

    let enabled = is_enabled(options, &context).await;
    let transport = resolve_transport(&context);
    let track = build_track_fn(&context, endpoint, debug_enabled(options), transport);

    let test_anonymous_id = context
        .test_hooks
        .as_ref()
        .and_then(|h| h.anonymous_id.clone());

    let anonymous_id_cell = Arc::new(Mutex::new(None));

    if enabled {
        let aid = test_anonymous_id
            .clone()
            .unwrap_or_else(|| resolve_project_id(options.base_url.as_deref()));
        {
            let mut g = anonymous_id_cell.lock().await;
            *g = Some(aid.clone());
        }

        let payload = json!({
            "config": get_telemetry_auth_config(options, &context),
            "runtime": runtime_for(&context),
            "database": database_for(&context),
            "framework": framework_for(&context),
            "environment": environment_for(&context),
            "systemInfo": system_info_for(&context),
            "packageManager": package_manager_for(&context),
        });

        let init = TelemetryEvent {
            event_type: "init".to_owned(),
            anonymous_id: Some(aid),
            payload,
        };
        let track_init = track.clone();
        tokio::spawn(async move {
            track_init(init).await;
        });
    }

    TelemetryPublisher {
        hard_noop: false,
        enabled,
        anonymous_id: anonymous_id_cell,
        base_url: options.base_url.clone(),
        test_anonymous_id,
        track,
    }
}
