//! Telemetry types shared with the Better Auth telemetry payload shape.

use serde::Serialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Provider / framework detection row (mirrors upstream `DetectionInfo`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DetectionInfo {
    pub name: String,
    pub version: Option<String>,
}

/// Runtime identification for Rust hosts (replaces Node/Bun/Deno detection).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub name: String,
    pub version: Option<String>,
}

/// Event sent to the telemetry collector or `custom_track`.
#[derive(Clone, Debug, Serialize)]
pub struct TelemetryEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "anonymousId", skip_serializing_if = "Option::is_none")]
    pub anonymous_id: Option<String>,
    pub payload: serde_json::Value,
}

impl TelemetryEvent {
    pub fn to_json_value(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self)
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub type CustomTrackFn = Arc<dyn Fn(TelemetryEvent) -> BoxFuture<'static, ()> + Send + Sync>;

/// Overrides used by integration tests (Vitest mocks replacement).
#[derive(Clone, Default)]
pub struct TelemetryTestHooks {
    pub anonymous_id: Option<String>,
    pub runtime: Option<RuntimeInfo>,
    pub database: Option<Option<DetectionInfo>>,
    pub framework: Option<Option<DetectionInfo>>,
    pub environment: Option<String>,
    pub system_info: Option<serde_json::Value>,
    pub package_manager: Option<Option<DetectionInfo>>,
}

/// Optional hints and hooks for telemetry collection.
#[derive(Clone, Default)]
pub struct TelemetryContext {
    pub database: Option<String>,
    pub adapter: Option<String>,
    pub skip_test_check: bool,
    pub custom_track: Option<CustomTrackFn>,
    pub http_transport: Option<Arc<dyn TelemetryHttpTransport>>,
    pub test_hooks: Option<TelemetryTestHooks>,
}

/// Async HTTP sink for telemetry JSON payloads.
pub trait TelemetryHttpTransport: Send + Sync {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<(), TelemetryHttpError>>;
}

/// Transport failures are intentionally opaque (upstream logs and continues).
#[derive(Clone, Debug)]
pub struct TelemetryHttpError(pub String);

impl std::fmt::Display for TelemetryHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for TelemetryHttpError {}
