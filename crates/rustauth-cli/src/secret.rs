use base64::Engine;
use rand::RngCore;
use serde::Serialize;

const DEFAULT_SECRET: &str = "rustauth-secret-123456789012345678901";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretSeverity {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretAssessment {
    pub severity: SecretSeverity,
    pub message: String,
}

pub fn generate_secret(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes.max(32)];
    rand::rngs::OsRng.fill_bytes(&mut buffer);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer)
}

pub fn assess_secret(secret: &str, production: bool) -> SecretAssessment {
    if secret.is_empty() {
        return error("RustAuth secret is missing.");
    }
    if production && secret == DEFAULT_SECRET {
        return error("The default RustAuth secret cannot be used in production.");
    }
    if looks_like_example_secret(secret) {
        return error("The configured secret looks like an example value.");
    }
    if secret.len() < 32 {
        return error("Secret is too short; use at least 32 bytes of random material.");
    }
    if character_classes(secret) < 3 {
        return error("Secret has low character diversity; generate a random secret.");
    }
    if repeated_single_character(secret) {
        return error("Secret has low entropy; generate a random secret.");
    }

    SecretAssessment {
        severity: SecretSeverity::Ok,
        message: "Secret strength looks good.".to_owned(),
    }
}

fn looks_like_example_secret(secret: &str) -> bool {
    let lower = secret.to_ascii_lowercase();
    lower.contains("secret-a-at-least-32-chars")
        || lower.contains("change-me")
        || lower.contains("example")
        || lower.contains("your-secret")
        || lower.contains("rustauth-example")
}

fn character_classes(secret: &str) -> usize {
    [
        secret
            .chars()
            .any(|character| character.is_ascii_lowercase()),
        secret
            .chars()
            .any(|character| character.is_ascii_uppercase()),
        secret.chars().any(|character| character.is_ascii_digit()),
        secret
            .chars()
            .any(|character| !character.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
}

fn repeated_single_character(secret: &str) -> bool {
    let mut chars = secret.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    chars.all(|character| character == first)
}

fn error(message: &str) -> SecretAssessment {
    SecretAssessment {
        severity: SecretSeverity::Error,
        message: message.to_owned(),
    }
}
