use base64::Engine;
use sha2::{Digest, Sha256};

/// SHA-256 digest encoded as standard Base64 (parity with upstream `hashToBase64`).
pub fn hash_to_base64(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}
