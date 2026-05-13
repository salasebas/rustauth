//! Telemetry-related environment variables use the **`OPENAUTH_*`** prefix only.

/// Returns the first non-empty env value among given keys (used for generic lookups like `NODE_ENV`).
pub fn first_env(keys: &[&'static str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn bool_env_single(key: &'static str, fallback: bool) -> bool {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => value != "0" && value.to_lowercase() != "false",
        _ => fallback,
    }
}

pub fn telemetry_endpoint() -> Option<String> {
    std::env::var("OPENAUTH_TELEMETRY_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty())
}

pub fn telemetry_enabled_env() -> bool {
    bool_env_single("OPENAUTH_TELEMETRY", false)
}

pub fn telemetry_debug_env() -> bool {
    bool_env_single("OPENAUTH_TELEMETRY_DEBUG", false)
}

pub fn node_env() -> Option<String> {
    first_env(&["NODE_ENV"])
}

pub fn is_test() -> bool {
    node_env().as_deref() == Some("test") || bool_env_single("TEST", false)
}

pub fn is_ci() -> bool {
    if std::env::var("CI").ok().as_deref() == Some("false") {
        return false;
    }
    [
        "BUILD_ID",
        "BUILD_NUMBER",
        "CI",
        "CI_APP_ID",
        "CI_BUILD_ID",
        "CI_BUILD_NUMBER",
        "CI_NAME",
        "CONTINUOUS_INTEGRATION",
        "RUN_ID",
    ]
    .into_iter()
    .any(|key| std::env::var_os(key).is_some())
}
