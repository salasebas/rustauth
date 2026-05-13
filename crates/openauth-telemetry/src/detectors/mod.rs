//! Host and toolchain detectors (Better Auth telemetry parity).

mod cargo_manifest;
mod database;
mod framework;
mod package_manager;
mod runtime;
mod system_info;

pub use database::detect_database;
pub use framework::detect_framework;
pub use package_manager::detect_package_manager;
pub use runtime::{detect_environment, detect_runtime};
pub use system_info::detect_system_info;
