use rustauth_core::crypto::{
    format_envelope, parse_envelope, symmetric_decrypt, symmetric_encrypt, SecretConfig,
};

#[test]
fn parse_envelope_returns_none_for_bare_ciphertext() {
    assert!(parse_envelope("abcdef1234567890").is_none());
}

#[test]
fn parse_envelope_parses_valid_versioned_payload() -> Result<(), Box<dyn std::error::Error>> {
    let envelope = parse_envelope("$oa$2$abcdef1234567890").ok_or("valid envelope")?;

    assert_eq!(envelope.version, 2);
    assert_eq!(envelope.ciphertext, "abcdef1234567890");
    Ok(())
}

#[test]
fn parse_envelope_rejects_negative_version() {
    assert!(parse_envelope("$oa$-1$abcdef").is_none());
}

#[test]
fn format_envelope_uses_rustauth_prefix() {
    assert_eq!(format_envelope(3, "deadbeef"), "$oa$3$deadbeef");
}

#[test]
fn symmetric_encrypt_with_string_secret_round_trips_without_envelope(
) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = symmetric_encrypt("secret-a-at-least-32-chars-long!!", "hello world")?;

    assert!(!encrypted.starts_with("$oa$"));
    assert_eq!(
        symmetric_decrypt("secret-a-at-least-32-chars-long!!", &encrypted)?,
        "hello world"
    );
    Ok(())
}

#[test]
fn symmetric_encrypt_with_secret_config_uses_current_version(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SecretConfig::new([(2, "secret-b-at-least-32-chars-long!!")]);
    let encrypted = symmetric_encrypt(&config, "rotated data")?;

    assert!(encrypted.starts_with("$oa$2$"));
    assert_eq!(symmetric_decrypt(&config, &encrypted)?, "rotated data");
    Ok(())
}

#[test]
fn symmetric_decrypt_accepts_old_key_in_rotation_config() -> Result<(), Box<dyn std::error::Error>>
{
    let old_config = SecretConfig::new([(1, "secret-a-at-least-32-chars-long!!")]);
    let encrypted = symmetric_encrypt(&old_config, "old data")?;
    let new_config = SecretConfig::new([
        (2, "secret-b-at-least-32-chars-long!!"),
        (1, "secret-a-at-least-32-chars-long!!"),
    ]);

    assert_eq!(symmetric_decrypt(&new_config, &encrypted)?, "old data");
    Ok(())
}

#[test]
fn symmetric_decrypt_uses_legacy_secret_for_bare_payload() -> Result<(), Box<dyn std::error::Error>>
{
    let bare = symmetric_encrypt("secret-a-at-least-32-chars-long!!", "legacy data")?;
    let config = SecretConfig::new([(2, "secret-b-at-least-32-chars-long!!")])
        .with_legacy_secret("secret-a-at-least-32-chars-long!!");

    assert_eq!(symmetric_decrypt(&config, &bare)?, "legacy data");
    Ok(())
}

#[test]
fn symmetric_decrypt_rejects_tampered_versioned_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let config = SecretConfig::new([(2, "secret-b-at-least-32-chars-long!!")]);
    let encrypted = symmetric_encrypt(&config, "rotated data")?;
    let tampered = format!("{encrypted}a");

    assert!(symmetric_decrypt(&config, &tampered).is_err());
    Ok(())
}
