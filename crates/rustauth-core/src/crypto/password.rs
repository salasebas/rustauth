//! Password hashing and verification.

use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params};
use unicode_normalization::UnicodeNormalization;

use crate::crypto::buffer::constant_time_equal;
use crate::error::RustAuthError;

const SALT_LEN: usize = 16;
const HASH_LEN: usize = 64;

fn scrypt_params() -> Result<Params, RustAuthError> {
    Params::new(14, 16, 1, HASH_LEN).map_err(|error| RustAuthError::PasswordHash(error.to_string()))
}

fn normalize_password(password: &str) -> String {
    password.nfkc().collect()
}

/// Hash a password using Better Auth's legacy-compatible scrypt format.
pub fn hash_password(password: &str) -> Result<String, RustAuthError> {
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut derived = [0_u8; HASH_LEN];
    scrypt(
        normalize_password(password).as_bytes(),
        &salt,
        &scrypt_params()?,
        &mut derived,
    )
    .map_err(|error| RustAuthError::PasswordHash(error.to_string()))?;

    Ok(format!("{}:{}", hex::encode(salt), hex::encode(derived)))
}

/// Verify a password against a `salt:hash` scrypt password hash.
pub fn verify_password(hash: &str, password: &str) -> Result<bool, RustAuthError> {
    let Some((salt_hex, hash_hex)) = hash.split_once(':') else {
        return Err(RustAuthError::PasswordHash(
            "password hash must use `salt:hash` format".to_owned(),
        ));
    };

    let salt =
        hex::decode(salt_hex).map_err(|error| RustAuthError::PasswordHash(error.to_string()))?;
    let expected =
        hex::decode(hash_hex).map_err(|error| RustAuthError::PasswordHash(error.to_string()))?;

    if expected.len() != HASH_LEN {
        return Err(RustAuthError::PasswordHash(format!(
            "password hash must decode to {HASH_LEN} bytes"
        )));
    }

    let mut derived = [0_u8; HASH_LEN];
    scrypt(
        normalize_password(password).as_bytes(),
        &salt,
        &scrypt_params()?,
        &mut derived,
    )
    .map_err(|error| RustAuthError::PasswordHash(error.to_string()))?;

    Ok(constant_time_equal(derived, expected))
}
