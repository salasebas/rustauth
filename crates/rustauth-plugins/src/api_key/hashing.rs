use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

const BETTER_AUTH_KEY_CHARSET: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub fn default_key_hasher(key: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

pub fn default_key_generator(length: usize, prefix: Option<&str>) -> String {
    let key = generate_alpha_string(length);
    match prefix {
        Some(prefix) => format!("{prefix}{key}"),
        None => key,
    }
}

fn generate_alpha_string(length: usize) -> String {
    let mut output = String::with_capacity(length);
    let mut random = [0_u8; 32];
    while output.len() < length {
        OsRng.fill_bytes(&mut random);
        for byte in random {
            if byte >= 208 {
                continue;
            }
            let index = usize::from(byte) % BETTER_AUTH_KEY_CHARSET.len();
            output.push(char::from(BETTER_AUTH_KEY_CHARSET[index]));
            if output.len() == length {
                break;
            }
        }
    }
    output
}
