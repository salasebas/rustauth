use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::error::OpenAuthError;
use sha2::{Digest, Sha256};

use super::options::MagicLinkFuture;

pub type CustomTokenHasher =
    Arc<dyn for<'a> Fn(&'a str) -> MagicLinkFuture<'a, String> + Send + Sync>;

#[derive(Clone)]
pub enum TokenStorage {
    Plain,
    Hashed,
    CustomHasher(CustomTokenHasher),
}

impl TokenStorage {
    pub fn custom<F>(hash: F) -> Self
    where
        F: for<'a> Fn(&'a str) -> MagicLinkFuture<'a, String> + Send + Sync + 'static,
    {
        Self::CustomHasher(Arc::new(hash))
    }

    pub(crate) async fn identifier(&self, token: &str) -> Result<String, OpenAuthError> {
        match self {
            Self::Plain => Ok(token.to_owned()),
            Self::Hashed => Ok(default_key_hasher(token)),
            Self::CustomHasher(hash) => hash(token).await,
        }
    }
}

pub fn generate_magic_link_token() -> String {
    generate_random_string(32)
}

pub fn default_key_hasher(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}
