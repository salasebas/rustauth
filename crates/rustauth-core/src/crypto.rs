//! Cryptographic primitives used by RustAuth core.

pub mod buffer;
mod envelope;
#[cfg(feature = "jose")]
pub mod jwe;
mod jwe_secret;
pub mod jwt;
pub mod password;
pub mod random;
mod symmetric;

pub use envelope::{format_envelope, parse_envelope, Envelope};
#[cfg(feature = "jose")]
pub use jwe::{
    symmetric_decode_jwt, symmetric_decode_jwt_with_salt, symmetric_encode_jwt,
    symmetric_encode_jwt_with_salt,
};
pub use jwe_secret::{JweSecret, JweSecretSource};
pub use symmetric::{
    build_secret_config, parse_secrets_env, symmetric_decrypt, symmetric_encrypt, validate_secrets,
    SecretConfig, SecretEntry, SecretSource,
};
