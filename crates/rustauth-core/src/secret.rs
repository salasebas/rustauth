use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
/// Secret string wrapper that redacts its value in `Debug` output.
pub struct SecretString(String);

impl SecretString {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the raw secret value.
    ///
    /// Prefer passing the secret directly to crypto or HTTP client code and
    /// avoid logging this value.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the raw secret value.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(REDACTED)")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.expose_secret()
    }
}
