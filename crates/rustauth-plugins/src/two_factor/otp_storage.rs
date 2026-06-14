use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_core::error::RustAuthError;

pub type OtpTransformFuture = Pin<Box<dyn Future<Output = Result<String, RustAuthError>> + Send>>;
pub type OtpHashFn = Arc<dyn Fn(String) -> OtpTransformFuture + Send + Sync>;
pub type OtpEncryptFn = Arc<dyn Fn(String) -> OtpTransformFuture + Send + Sync>;
pub type OtpDecryptFn = Arc<dyn Fn(String) -> OtpTransformFuture + Send + Sync>;

#[derive(Clone, Default)]
pub enum OtpStorage {
    #[default]
    Plain,
    Encrypted,
    Hashed,
    CustomHash(OtpHashFn),
    CustomEncrypt {
        encrypt: OtpEncryptFn,
        decrypt: OtpDecryptFn,
    },
}

impl std::fmt::Debug for OtpStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => formatter.write_str("Plain"),
            Self::Encrypted => formatter.write_str("Encrypted"),
            Self::Hashed => formatter.write_str("Hashed"),
            Self::CustomHash(_) => formatter.write_str("CustomHash(<hash>)"),
            Self::CustomEncrypt { .. } => formatter.write_str("CustomEncrypt(<encrypt/decrypt>)"),
        }
    }
}
