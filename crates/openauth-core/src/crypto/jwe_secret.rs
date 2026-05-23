use crate::crypto::SecretConfig;
use crate::error::OpenAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JweSecret {
    pub(crate) value: String,
}

/// Secret material accepted by Better Auth-compatible JWE helpers.
pub trait JweSecretSource {
    fn current_jwe_secret(&self) -> Result<String, OpenAuthError>;
    fn all_jwe_secrets(&self) -> Result<Vec<JweSecret>, OpenAuthError>;
}

impl JweSecretSource for str {
    fn current_jwe_secret(&self) -> Result<String, OpenAuthError> {
        Ok(self.to_owned())
    }

    fn all_jwe_secrets(&self) -> Result<Vec<JweSecret>, OpenAuthError> {
        Ok(vec![JweSecret {
            value: self.to_owned(),
        }])
    }
}

impl JweSecretSource for String {
    fn current_jwe_secret(&self) -> Result<String, OpenAuthError> {
        self.as_str().current_jwe_secret()
    }

    fn all_jwe_secrets(&self) -> Result<Vec<JweSecret>, OpenAuthError> {
        self.as_str().all_jwe_secrets()
    }
}

impl JweSecretSource for SecretConfig {
    fn current_jwe_secret(&self) -> Result<String, OpenAuthError> {
        self.keys
            .get(&self.current_version)
            .cloned()
            .ok_or_else(|| {
                OpenAuthError::InvalidSecretConfig(format!(
                    "secret version {} not found in keys",
                    self.current_version
                ))
            })
    }

    fn all_jwe_secrets(&self) -> Result<Vec<JweSecret>, OpenAuthError> {
        let mut secrets = Vec::new();
        secrets.push(JweSecret {
            value: self.current_jwe_secret()?,
        });
        for (version, value) in &self.keys {
            if *version != self.current_version {
                secrets.push(JweSecret {
                    value: value.clone(),
                });
            }
        }
        if let Some(legacy_secret) = &self.legacy_secret {
            if !secrets.iter().any(|secret| secret.value == *legacy_secret) {
                secrets.push(JweSecret {
                    value: legacy_secret.clone(),
                });
            }
        }
        Ok(secrets)
    }
}
