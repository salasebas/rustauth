//! Access control helpers inspired by Better Auth's access plugin.

mod authorize;
mod control;
mod error;
mod types;

pub use control::{create_access_control, request, role, statements, AccessControl};
pub use error::AccessError;
pub use types::{AccessRequest, Connector, ResourceRequest, Role, Statements};

/// Better Auth upstream plugin identifier.
pub const UPSTREAM_PLUGIN_ID: &str = "access";
