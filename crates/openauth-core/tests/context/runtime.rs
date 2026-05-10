use openauth_core::context::{
    create_auth_context, create_auth_context_with_environment, AuthEnvironment,
};
use openauth_core::options::{
    OpenAuthOptions, PasswordOptions, RateLimitOptions, RateLimitStorageOption, SessionOptions,
};

#[test]
fn create_auth_context_resolves_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(ctx.base_path, "/api/auth");
    assert_eq!(ctx.session_config.expires_in, 60 * 60 * 24 * 7);
    assert_eq!(ctx.password.config.min_password_length, 8);
    Ok(())
}

#[test]
fn create_auth_context_applies_session_and_password_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        session: SessionOptions {
            expires_in: Some(120),
            update_age: Some(30),
            fresh_age: Some(10),
            ..SessionOptions::default()
        },
        password: PasswordOptions {
            min_password_length: 12,
            max_password_length: 256,
        },
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(ctx.session_config.expires_in, 120);
    assert_eq!(ctx.session_config.update_age, 30);
    assert_eq!(ctx.password.config.max_password_length, 256);
    Ok(())
}

#[test]
fn create_auth_context_rejects_missing_secret_in_production() {
    let result = create_auth_context(OpenAuthOptions {
        production: true,
        ..OpenAuthOptions::default()
    });

    assert!(result.is_err());
}

#[test]
fn create_auth_context_uses_better_auth_secret_from_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        OpenAuthOptions::default(),
        AuthEnvironment {
            better_auth_secret: Some("env-secret-at-least-32-chars-long!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "env-secret-at-least-32-chars-long!!");
    Ok(())
}

#[test]
fn create_auth_context_prefers_options_secret_over_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        OpenAuthOptions {
            secret: Some("option-secret-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        AuthEnvironment {
            better_auth_secret: Some("env-secret-at-least-32-chars-long!!".to_owned()),
            auth_secret: Some("auth-secret-at-least-32-chars-long!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "option-secret-at-least-32-chars-long!!");
    Ok(())
}

#[test]
fn create_auth_context_builds_secret_config_from_environment_secrets(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        OpenAuthOptions::default(),
        AuthEnvironment {
            better_auth_secrets: Some(
                "2:secret-b-at-least-32-chars-long!!,1:secret-a-at-least-32-chars-long!!"
                    .to_owned(),
            ),
            better_auth_secret: Some("legacy-secret-at-least-32-chars!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "secret-b-at-least-32-chars-long!!");
    assert!(matches!(
        ctx.secret_config,
        openauth_core::context::SecretMaterial::Rotating(_)
    ));
    Ok(())
}

#[test]
fn create_auth_context_rejects_external_rate_limit_storage_without_storage_contract() {
    let result = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            storage: RateLimitStorageOption::Database,
            ..RateLimitOptions::default()
        },
        ..OpenAuthOptions::default()
    });

    assert!(matches!(
        result,
        Err(openauth_core::error::OpenAuthError::InvalidConfig(message))
            if message.contains("custom_storage")
    ));
}
