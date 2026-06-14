use serde::{Deserialize, Serialize};

use rustauth_core::crypto::{symmetric_decode_jwt, symmetric_encode_jwt, SecretConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Claims {
    subject: String,
}

#[test]
fn symmetric_jwe_round_trips_with_string_secret() -> Result<(), Box<dyn std::error::Error>> {
    let claims = Claims {
        subject: "user_123".to_owned(),
    };

    let token = symmetric_encode_jwt(&claims, "secret-a-at-least-32-chars-long!!", 300)?;
    let decoded = symmetric_decode_jwt::<Claims, _>(&token, "secret-a-at-least-32-chars-long!!")?;

    assert_eq!(decoded, Some(claims));
    Ok(())
}

#[test]
fn symmetric_jwe_decodes_with_rotated_secret_config() -> Result<(), Box<dyn std::error::Error>> {
    let claims = Claims {
        subject: "user_123".to_owned(),
    };
    let old_config = SecretConfig::new([(1, "secret-a-at-least-32-chars-long!!")]);
    let rotated_config = SecretConfig::new([
        (2, "secret-b-at-least-32-chars-long!!"),
        (1, "secret-a-at-least-32-chars-long!!"),
    ]);

    let token = symmetric_encode_jwt(&claims, &old_config, 300)?;
    let decoded = symmetric_decode_jwt::<Claims, _>(&token, &rotated_config)?;

    assert_eq!(decoded, Some(claims));
    Ok(())
}

#[test]
fn symmetric_jwe_decodes_with_legacy_secret() -> Result<(), Box<dyn std::error::Error>> {
    let claims = Claims {
        subject: "user_123".to_owned(),
    };
    let rotated_config = SecretConfig::new([(2, "secret-b-at-least-32-chars-long!!")])
        .with_legacy_secret("secret-a-at-least-32-chars-long!!");

    let token = symmetric_encode_jwt(&claims, "secret-a-at-least-32-chars-long!!", 300)?;
    let decoded = symmetric_decode_jwt::<Claims, _>(&token, &rotated_config)?;

    assert_eq!(decoded, Some(claims));
    Ok(())
}

#[test]
fn symmetric_jwe_rejects_mismatched_kid_without_fallback() -> Result<(), Box<dyn std::error::Error>>
{
    let claims = Claims {
        subject: "user_123".to_owned(),
    };
    let old_config = SecretConfig::new([(1, "secret-a-at-least-32-chars-long!!")]);
    let wrong_config = SecretConfig::new([(2, "secret-b-at-least-32-chars-long!!")]);

    let token = symmetric_encode_jwt(&claims, &old_config, 300)?;
    let decoded = symmetric_decode_jwt::<Claims, _>(&token, &wrong_config)?;

    assert_eq!(decoded, None);
    Ok(())
}

#[test]
fn symmetric_jwe_accepts_tokens_inside_clock_tolerance() -> Result<(), Box<dyn std::error::Error>> {
    let claims = Claims {
        subject: "user_123".to_owned(),
    };

    let token = symmetric_encode_jwt(&claims, "secret-a-at-least-32-chars-long!!", 0)?;
    let decoded = symmetric_decode_jwt::<Claims, _>(&token, "secret-a-at-least-32-chars-long!!")?;

    assert_eq!(decoded, Some(claims));
    Ok(())
}
