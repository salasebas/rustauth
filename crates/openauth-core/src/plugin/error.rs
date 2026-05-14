//! Plugin error code registry types.

use crate::error::OpenAuthError;

/// Error code contributed by a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginErrorCode {
    pub code: String,
    pub message: String,
}

impl PluginErrorCode {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn validate(&self) -> Result<(), OpenAuthError> {
        if self.code.is_empty()
            || !self
                .code
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_uppercase())
        {
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin error code `{}` must use upper snake case",
                self.code
            )));
        }
        Ok(())
    }
}
