//! Symmetric encryption and secret rotation support.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

use super::envelope::{format_envelope, parse_envelope};
use crate::error::RustAuthError;

const DEFAULT_SECRET: &str = "better-auth-secret-12345678901234567890";

/// Versioned secret entry.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretEntry {
    pub version: u32,
    pub value: String,
}

impl SecretEntry {
    pub fn new(version: u32, value: impl Into<String>) -> Self {
        Self {
            version,
            value: value.into(),
        }
    }
}

impl fmt::Debug for SecretEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEntry")
            .field("version", &self.version)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Secret rotation configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretConfig {
    pub keys: BTreeMap<u32, String>,
    pub current_version: u32,
    pub legacy_secret: Option<String>,
}

impl SecretConfig {
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (u32, S)>,
        S: Into<String>,
    {
        let mut keys = BTreeMap::new();
        let mut current_version = None;
        for (version, value) in entries {
            if current_version.is_none() {
                current_version = Some(version);
            }
            keys.insert(version, value.into());
        }

        Self {
            keys,
            current_version: current_version.unwrap_or(0),
            legacy_secret: None,
        }
    }

    pub fn with_legacy_secret(mut self, secret: impl Into<String>) -> Self {
        self.legacy_secret = Some(secret.into());
        self
    }

    fn current_secret(&self) -> Result<&str, RustAuthError> {
        self.keys
            .get(&self.current_version)
            .map(String::as_str)
            .ok_or_else(|| {
                RustAuthError::InvalidSecretConfig(format!(
                    "secret version {} not found in keys",
                    self.current_version
                ))
            })
    }
}

impl fmt::Debug for SecretConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretConfig")
            .field("key_versions", &self.keys.keys().collect::<Vec<_>>())
            .field("current_version", &self.current_version)
            .field(
                "legacy_secret",
                &self.legacy_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Parse comma-separated `version:secret` entries.
pub fn parse_secrets_env(value: Option<&str>) -> Result<Option<Vec<SecretEntry>>, RustAuthError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        let Some((version, secret)) = entry.split_once(':') else {
            return Err(RustAuthError::InvalidSecretConfig(format!(
                "invalid secret entry `{entry}`; expected `<version>:<secret>`"
            )));
        };
        let version = version.trim().parse::<u32>().map_err(|_| {
            RustAuthError::InvalidSecretConfig(format!(
                "invalid version `{}`; version must be a non-negative integer",
                version.trim()
            ))
        })?;
        let secret = secret.trim();
        if secret.is_empty() {
            return Err(RustAuthError::InvalidSecretConfig(format!(
                "empty secret value for version {version}"
            )));
        }
        entries.push(SecretEntry::new(version, secret));
    }

    Ok(Some(entries))
}

/// Validate versioned secrets and return warnings for weak current secrets.
pub fn validate_secrets(secrets: &[SecretEntry]) -> Result<Vec<String>, RustAuthError> {
    if secrets.is_empty() {
        return Err(RustAuthError::InvalidSecretConfig(
            "`secrets` must contain at least one entry".to_owned(),
        ));
    }

    let mut seen = HashSet::new();
    for secret in secrets {
        if secret.value.is_empty() {
            return Err(RustAuthError::InvalidSecretConfig(format!(
                "empty secret value for version {}",
                secret.version
            )));
        }
        if !seen.insert(secret.version) {
            return Err(RustAuthError::InvalidSecretConfig(format!(
                "duplicate version {}",
                secret.version
            )));
        }
    }

    let mut warnings = Vec::new();
    let current = &secrets[0];
    if current.value.len() < 32 {
        warnings.push(format!(
            "current secret version {} should be at least 32 characters long",
            current.version
        ));
    }
    if estimate_entropy(&current.value) < 120.0 {
        warnings.push("current secret appears low entropy".to_owned());
    }

    Ok(warnings)
}

/// Build a rotation config from validated entries.
pub fn build_secret_config(
    secrets: &[SecretEntry],
    legacy_secret: &str,
) -> Result<SecretConfig, RustAuthError> {
    validate_secrets(secrets)?;
    let mut config = SecretConfig::new(
        secrets
            .iter()
            .map(|entry| (entry.version, entry.value.clone())),
    );
    if !legacy_secret.is_empty() && legacy_secret != DEFAULT_SECRET {
        config.legacy_secret = Some(legacy_secret.to_owned());
    }
    Ok(config)
}

fn estimate_entropy(value: &str) -> f64 {
    let unique = value.chars().collect::<HashSet<_>>().len();
    if unique == 0 {
        return 0.0;
    }
    (unique as f64).log2() * value.chars().count() as f64
}

fn derive_key(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn raw_encrypt(secret: &str, data: &str) -> Result<String, RustAuthError> {
    let key = derive_key(secret);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data.as_bytes())
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;

    let mut payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(hex::encode(payload))
}

fn raw_decrypt(secret: &str, hex_payload: &str) -> Result<String, RustAuthError> {
    let payload =
        hex::decode(hex_payload).map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    if payload.len() <= 24 {
        return Err(RustAuthError::Crypto(
            "encrypted payload is too short".to_owned(),
        ));
    }

    let (nonce, ciphertext) = payload.split_at(24);
    let key = derive_key(secret);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;

    String::from_utf8(plaintext).map_err(|error| RustAuthError::Crypto(error.to_string()))
}

/// Secret material accepted by symmetric encryption helpers.
pub trait SecretSource {
    fn encrypt_current(&self, data: &str) -> Result<String, RustAuthError>;
    fn decrypt_payload(&self, data: &str) -> Result<String, RustAuthError>;
}

impl SecretSource for &str {
    fn encrypt_current(&self, data: &str) -> Result<String, RustAuthError> {
        raw_encrypt(self, data)
    }

    fn decrypt_payload(&self, data: &str) -> Result<String, RustAuthError> {
        raw_decrypt(self, data)
    }
}

impl SecretSource for String {
    fn encrypt_current(&self, data: &str) -> Result<String, RustAuthError> {
        self.as_str().encrypt_current(data)
    }

    fn decrypt_payload(&self, data: &str) -> Result<String, RustAuthError> {
        self.as_str().decrypt_payload(data)
    }
}

impl SecretSource for &SecretConfig {
    fn encrypt_current(&self, data: &str) -> Result<String, RustAuthError> {
        let ciphertext = raw_encrypt(self.current_secret()?, data)?;
        Ok(format_envelope(self.current_version, &ciphertext))
    }

    fn decrypt_payload(&self, data: &str) -> Result<String, RustAuthError> {
        if let Some(envelope) = parse_envelope(data) {
            let secret = self.keys.get(&envelope.version).ok_or_else(|| {
                RustAuthError::InvalidSecretConfig(format!(
                    "secret version {} not found in keys; key may have been retired",
                    envelope.version
                ))
            })?;
            return raw_decrypt(secret, &envelope.ciphertext);
        }

        if let Some(legacy_secret) = &self.legacy_secret {
            return raw_decrypt(legacy_secret, data);
        }

        Err(RustAuthError::InvalidSecretConfig(
            "cannot decrypt legacy bare payload: no legacy secret available".to_owned(),
        ))
    }
}

/// Encrypt a string with either a raw secret or a versioned secret config.
pub fn symmetric_encrypt(key: impl SecretSource, data: &str) -> Result<String, RustAuthError> {
    key.encrypt_current(data)
}

/// Decrypt a string with either a raw secret or a versioned secret config.
pub fn symmetric_decrypt(key: impl SecretSource, data: &str) -> Result<String, RustAuthError> {
    key.decrypt_payload(data)
}
