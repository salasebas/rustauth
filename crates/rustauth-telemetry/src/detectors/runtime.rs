use crate::env::{is_ci, is_test, rust_env};
use crate::types::RuntimeInfo;

pub fn detect_runtime() -> RuntimeInfo {
    RuntimeInfo {
        name: "rust".to_owned(),
        version: std::env::var("RUSTC_VERSION")
            .ok()
            .filter(|s| !s.is_empty()),
    }
}

pub fn detect_environment() -> String {
    if rust_env().as_deref() == Some("production") {
        return "production".to_owned();
    }
    if is_ci() {
        return "ci".to_owned();
    }
    if is_test() {
        return "test".to_owned();
    }
    "development".to_owned()
}
