//! Plugin rate-limit rule contributions.

use crate::options::RateLimitRule;

/// Rate-limit rule contributed by a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRateLimitRule {
    pub path: String,
    pub rule: RateLimitRule,
}

impl PluginRateLimitRule {
    pub fn new(path: impl Into<String>, rule: RateLimitRule) -> Self {
        Self {
            path: path.into(),
            rule,
        }
    }
}
