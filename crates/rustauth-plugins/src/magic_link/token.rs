use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rustauth_core::error::RustAuthError;
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

    pub(crate) async fn identifier(&self, token: &str) -> Result<String, RustAuthError> {
        match self {
            Self::Plain => Ok(token.to_owned()),
            Self::Hashed => Ok(default_key_hasher(token)),
            Self::CustomHasher(hash) => hash(token).await,
        }
    }
}

pub fn generate_magic_link_token() -> String {
    const LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ACCEPT_LIMIT: u8 = 52 * 4;
    let mut output = String::with_capacity(32);
    while output.len() < 32 {
        let mut random = [0_u8; 32];
        OsRng.fill_bytes(&mut random);
        for byte in random {
            if byte >= ACCEPT_LIMIT {
                continue;
            }
            output.push(char::from(LETTERS[usize::from(byte % 52)]));
            if output.len() == 32 {
                break;
            }
        }
    }
    output
}

pub fn default_key_hasher(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}
