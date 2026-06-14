//! Plugin endpoint contributions.

use crate::api::AsyncAuthEndpoint;

/// Async endpoint contributed by a plugin.
pub type PluginEndpoint = AsyncAuthEndpoint;
