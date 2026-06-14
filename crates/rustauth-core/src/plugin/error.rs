//! Plugin error code registry types.

use crate::error::RustAuthError;
use crate::error_codes::ErrorCode;

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

    pub fn validate(&self) -> Result<(), RustAuthError> {
        if self.code.is_empty()
            || !self
                .code
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_uppercase())
        {
            return Err(RustAuthError::InvalidConfig(format!(
                "plugin error code `{}` must use upper snake case",
                self.code
            )));
        }
        Ok(())
    }
}

impl ErrorCode for PluginErrorCode {
    fn as_str(&self) -> &str {
        &self.code
    }

    fn message(&self) -> &str {
        &self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::ErrorCode;

    fn assert_error_code(code: impl ErrorCode, expected_code: &str, expected_message: &str) {
        assert_eq!(code.as_str(), expected_code);
        assert_eq!(code.message(), expected_message);
    }

    #[test]
    fn plugin_error_code_implements_error_code_trait() {
        assert_error_code(
            PluginErrorCode::new("PLUGIN_FAILURE", "Plugin failure"),
            "PLUGIN_FAILURE",
            "Plugin failure",
        );
    }
}
