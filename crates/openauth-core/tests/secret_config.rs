use openauth_core::crypto::{
    build_secret_config, parse_secrets_env, validate_secrets, SecretEntry,
};

#[test]
fn parse_secrets_env_returns_none_for_missing_or_empty() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(parse_secrets_env(None)?, None);
    assert_eq!(parse_secrets_env(Some(""))?, None);
    assert_eq!(parse_secrets_env(Some("   "))?, None);
    Ok(())
}

#[test]
fn parse_secrets_env_trims_entries_and_values() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = parse_secrets_env(Some("1: foo , 2:bar "))?.ok_or("secrets")?;

    assert_eq!(
        secrets,
        vec![SecretEntry::new(1, "foo"), SecretEntry::new(2, "bar")]
    );
    Ok(())
}

#[test]
fn parse_secrets_env_rejects_entry_without_colon() {
    assert!(parse_secrets_env(Some("noseparator")).is_err());
}

#[test]
fn parse_secrets_env_rejects_negative_version() {
    assert!(parse_secrets_env(Some("-1:secret")).is_err());
}

#[test]
fn parse_secrets_env_rejects_empty_secret_value() {
    assert!(parse_secrets_env(Some("1:")).is_err());
}

#[test]
fn validate_secrets_rejects_empty_array() {
    assert!(validate_secrets(&[]).is_err());
}

#[test]
fn validate_secrets_rejects_duplicate_versions() {
    let secrets = [
        SecretEntry::new(1, "secret-a-at-least-32-chars-long!!"),
        SecretEntry::new(1, "secret-b-at-least-32-chars-long!!"),
    ];

    assert!(validate_secrets(&secrets).is_err());
}

#[test]
fn build_secret_config_uses_first_entry_as_current_version(
) -> Result<(), Box<dyn std::error::Error>> {
    let secrets = [
        SecretEntry::new(2, "secret-b-at-least-32-chars-long!!"),
        SecretEntry::new(1, "secret-a-at-least-32-chars-long!!"),
    ];

    let config = build_secret_config(&secrets, "")?;

    assert_eq!(config.current_version, 2);
    assert_eq!(
        config.keys.get(&1).map(String::as_str),
        Some("secret-a-at-least-32-chars-long!!")
    );
    Ok(())
}

#[test]
fn build_secret_config_includes_non_default_legacy_secret() -> Result<(), Box<dyn std::error::Error>>
{
    let secrets = [SecretEntry::new(1, "secret-a-at-least-32-chars-long!!")];

    let config = build_secret_config(&secrets, "legacy-secret-at-least-32-chars!!")?;

    assert_eq!(
        config.legacy_secret.as_deref(),
        Some("legacy-secret-at-least-32-chars!!")
    );
    Ok(())
}

#[test]
fn build_secret_config_excludes_default_legacy_secret() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = [SecretEntry::new(1, "secret-a-at-least-32-chars-long!!")];

    let config = build_secret_config(&secrets, "better-auth-secret-12345678901234567890")?;

    assert_eq!(config.legacy_secret, None);
    Ok(())
}
