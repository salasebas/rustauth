//! Deterministic password callbacks for integration tests where scrypt is not
//! the subject under test.

use crate::crypto::password::{hash_password, verify_password};
use crate::error::RustAuthError;
use crate::options::{DeploymentMode, EmailPasswordOptions, PasswordOptions, RustAuthOptions};

/// Deterministic password hashing for route/plugin fixtures.
pub fn fast_hash_password(password: &str) -> Result<String, RustAuthError> {
    Ok(format!("test-password:{password}"))
}

/// Deterministic password verification paired with [`fast_hash_password`].
pub fn fast_verify_password(hash: &str, password: &str) -> Result<bool, RustAuthError> {
    Ok(hash == format!("test-password:{password}"))
}

/// Real scrypt password options for tests that assert stored hash shape.
pub fn real_password_options() -> PasswordOptions {
    PasswordOptions::default()
        .hash_password(hash_password)
        .verify_password(verify_password)
}

/// Development and email/password defaults for integration test routers.
pub fn with_integration_test_defaults(mut options: RustAuthOptions) -> RustAuthOptions {
    if options.mode != DeploymentMode::Production {
        options.mode = DeploymentMode::Development;
    }
    if !options.email_password.enabled {
        options.email_password = EmailPasswordOptions::new().enabled(true);
    }
    apply_fast_password_defaults(options)
}

/// Wire fast password callbacks unless the caller already configured hashing.
pub fn apply_fast_password_defaults(mut options: RustAuthOptions) -> RustAuthOptions {
    if options.password.hash_password.is_none() {
        options.password = options
            .password
            .hash_password(fast_hash_password)
            .verify_password(fast_verify_password);
    }
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_password_callbacks_roundtrip() -> Result<(), RustAuthError> {
        let hash = fast_hash_password("secret123")?;
        assert!(fast_verify_password(&hash, "secret123")?);
        assert!(!fast_verify_password(&hash, "wrong")?);
        Ok(())
    }
}
