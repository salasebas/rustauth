use rustauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use rustauth_core::error::RustAuthError;

use super::options::{BackupCodeOptions, BackupCodeStorage};

pub fn generate_backup_codes(options: &BackupCodeOptions) -> Vec<String> {
    (0..options.amount)
        .map(|_| {
            let raw = rustauth_core::crypto::random::generate_random_string(options.length);
            let split = raw.len().min(5);
            format!("{}-{}", &raw[..split], &raw[split..])
        })
        .collect()
}

pub fn encode_backup_codes(
    codes: &[String],
    secret: &str,
    options: &BackupCodeOptions,
) -> Result<String, RustAuthError> {
    let json =
        serde_json::to_string(codes).map_err(|error| RustAuthError::Api(error.to_string()))?;
    match options.storage {
        BackupCodeStorage::Plain => Ok(json),
        BackupCodeStorage::Encrypted => symmetric_encrypt(secret, &json),
    }
}

pub fn decode_backup_codes(
    encoded: &str,
    secret: &str,
    options: &BackupCodeOptions,
) -> Result<Vec<String>, RustAuthError> {
    let json = match options.storage {
        BackupCodeStorage::Plain => encoded.to_owned(),
        BackupCodeStorage::Encrypted => symmetric_decrypt(secret, encoded)?,
    };
    serde_json::from_str(&json).map_err(|error| RustAuthError::Api(error.to_string()))
}

pub fn consume_backup_code(codes: &[String], code: &str) -> Option<Vec<String>> {
    codes.iter().any(|candidate| candidate == code).then(|| {
        codes
            .iter()
            .filter(|candidate| *candidate != code)
            .cloned()
            .collect()
    })
}
