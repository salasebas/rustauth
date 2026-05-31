use openauth_core::auth::oauth::{
    decrypt_oauth_token, generate_oauth_state, handle_oauth_user_info, missing_email_log_message,
    parse_oauth_state, set_token_util, HandleOAuthUserInfoInput, OAuthAccountInput,
    OAuthStateInput, OAuthStateLink, OAuthUserInfo, OAuthUserInfoError,
};
use openauth_core::context::create_auth_context;
#[cfg(feature = "jose")]
use openauth_core::crypto::symmetric_decode_jwt_with_salt;
#[cfg(feature = "jose")]
use openauth_core::db::Account;
use openauth_core::db::{DbValue, MemoryAdapter};
use openauth_core::options::{
    AccountLinkingOptions, AccountOptions, OAuthStateStoreStrategy, OpenAuthOptions,
};
use openauth_core::user::{CreateUserInput, DbUserStore};
use time::{Duration, OffsetDateTime};

#[test]
fn oauth_token_utils_encrypt_decrypt_and_tolerate_legacy_plain_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted_context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        account: AccountOptions {
            encrypt_oauth_tokens: true,
            ..AccountOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;
    let plain_context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(set_token_util(None, &encrypted_context)?, None);
    assert_eq!(decrypt_oauth_token("", &encrypted_context)?, "");
    assert_eq!(
        decrypt_oauth_token("ya29.a0ARW5m7hQ_some-token", &encrypted_context)?,
        "ya29.a0ARW5m7hQ_some-token"
    );
    assert_eq!(
        set_token_util(Some("plain-token"), &plain_context)?.as_deref(),
        Some("plain-token")
    );

    let encrypted = set_token_util(Some("secret-token"), &encrypted_context)?
        .ok_or("missing encrypted token")?;
    assert_ne!(encrypted, "secret-token");
    assert_eq!(
        decrypt_oauth_token(&encrypted, &encrypted_context)?,
        "secret-token"
    );
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_encrypts_all_stored_tokens_exactly_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        base_url: Some("https://app.example.com".to_owned()),
        account: AccountOptions {
            encrypt_oauth_tokens: true,
            ..AccountOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;

    let result = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("access-1")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(result.error.is_none());

    let accounts = adapter.records("account").await;
    let account = accounts.first().ok_or("missing account")?;
    let stored = |field: &str| match account.get(field) {
        Some(DbValue::String(value)) => Ok(value.clone()),
        _ => Err(format!("missing stored field `{field}`")),
    };
    let stored_access = stored("access_token")?;
    let stored_refresh = stored("refresh_token")?;
    let stored_id = stored("id_token")?;

    // No token field (including id_token) is persisted in plaintext.
    assert_ne!(stored_access, "access-1");
    assert_ne!(stored_refresh, "refresh");
    assert_ne!(stored_id, "id-token");

    // A single decrypt step recovers the originals: id_token follows the same
    // policy as access/refresh, and access/refresh are not double-encrypted.
    assert_eq!(decrypt_oauth_token(&stored_access, &context)?, "access-1");
    assert_eq!(decrypt_oauth_token(&stored_refresh, &context)?, "refresh");
    assert_eq!(decrypt_oauth_token(&stored_id, &context)?, "id-token");
    Ok(())
}

#[tokio::test]
async fn oauth_state_cookie_strategy_round_trips_without_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = test_context(AccountOptions::default())?;

    let state = generate_oauth_state(
        &context,
        None,
        OAuthStateInput {
            callback_url: "https://app.example.com/callback".to_owned(),
            error_url: Some("https://app.example.com/error".to_owned()),
            new_user_url: Some("https://app.example.com/new".to_owned()),
            link: Some(OAuthStateLink {
                email: "ada@example.com".to_owned(),
                user_id: "user_1".to_owned(),
            }),
            request_sign_up: true,
            ..OAuthStateInput::default()
        },
    )
    .await?;

    assert_eq!(state.data.callback_url, "https://app.example.com/callback");
    assert_eq!(state.data.code_verifier.len(), 128);
    assert!(state.data.expires_at > OffsetDateTime::now_utc());

    let parsed = parse_oauth_state(&context, None, &state.state).await?;

    assert_eq!(parsed.callback_url, "https://app.example.com/callback");
    assert_eq!(
        parsed.link.as_ref().map(|link| link.user_id.as_str()),
        Some("user_1")
    );
    Ok(())
}

#[tokio::test]
async fn parse_oauth_state_rejects_cookie_state_with_wrong_secret(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = test_context(AccountOptions::default())?;
    let other_context = create_auth_context(OpenAuthOptions {
        secret: Some("different-secret-at-least-32-chars!".to_owned()),
        base_url: Some("https://app.example.com".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let state = generate_oauth_state(
        &context,
        None,
        OAuthStateInput {
            callback_url: "https://app.example.com/callback".to_owned(),
            ..OAuthStateInput::default()
        },
    )
    .await?;

    assert!(parse_oauth_state(&other_context, None, &state.state)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn oauth_state_database_strategy_persists_and_rejects_expired_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions {
        store_state_strategy: OAuthStateStoreStrategy::Database,
        ..AccountOptions::default()
    })?;
    let state = generate_oauth_state(
        &context,
        Some(&adapter),
        OAuthStateInput {
            callback_url: "https://app.example.com/callback".to_owned(),
            ..OAuthStateInput::default()
        },
    )
    .await?;

    assert_eq!(adapter.len("verification").await, 1);
    let parsed = parse_oauth_state(&context, Some(&adapter), &state.state).await?;
    assert_eq!(parsed.callback_url, "https://app.example.com/callback");
    assert!(parse_oauth_state(&context, Some(&adapter), &state.state)
        .await
        .is_err());

    let expired = generate_oauth_state(
        &context,
        Some(&adapter),
        OAuthStateInput {
            callback_url: "https://app.example.com/expired".to_owned(),
            expires_at: Some(OffsetDateTime::now_utc() - Duration::seconds(1)),
            ..OAuthStateInput::default()
        },
    )
    .await?;
    assert!(parse_oauth_state(&context, Some(&adapter), &expired.state)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn oauth_state_cookie_strategy_is_single_use_with_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    // Default account options use the cookie strategy.
    let context = test_context(AccountOptions::default())?;

    let state = generate_oauth_state(
        &context,
        Some(&adapter),
        OAuthStateInput {
            callback_url: "https://app.example.com/callback".to_owned(),
            ..OAuthStateInput::default()
        },
    )
    .await?;

    // A single-use marker is persisted even though the payload itself travels in
    // the encrypted cookie state.
    assert_eq!(adapter.len("verification").await, 1);

    let parsed = parse_oauth_state(&context, Some(&adapter), &state.state).await?;
    assert_eq!(parsed.callback_url, "https://app.example.com/callback");

    // The marker is consumed on first parse, so replaying the same cookie state
    // is rejected within its TTL (OPE-19).
    assert!(parse_oauth_state(&context, Some(&adapter), &state.state)
        .await
        .is_err());
    assert_eq!(adapter.len("verification").await, 0);

    Ok(())
}

#[tokio::test]
async fn oauth_state_cookie_strategy_without_adapter_skips_single_use_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = test_context(AccountOptions::default())?;

    let state = generate_oauth_state(
        &context,
        None,
        OAuthStateInput {
            callback_url: "https://app.example.com/callback".to_owned(),
            ..OAuthStateInput::default()
        },
    )
    .await?;

    // Without an adapter no server-side marker can be stored, so the stateless
    // cookie state stays parseable. Single-use enforcement requires an adapter,
    // which every real sign-in/callback flow provides.
    assert!(parse_oauth_state(&context, None, &state.state)
        .await
        .is_ok());
    assert!(parse_oauth_state(&context, None, &state.state)
        .await
        .is_ok());

    Ok(())
}

#[cfg(feature = "jose")]
#[tokio::test]
async fn handle_oauth_user_info_sets_account_cookie_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions {
        store_account_cookie: true,
        ..AccountOptions::default()
    })?;

    let result = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("access-1")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;

    let cookie = result
        .cookies
        .iter()
        .find(|cookie| cookie.name == context.auth_cookies.account_data.name)
        .ok_or("missing account cookie")?;
    let decoded: Option<Account> = symmetric_decode_jwt_with_salt(
        &cookie.value,
        &context.secret_config,
        "better-auth-account",
    )?;
    let account = decoded.ok_or("account cookie did not decode")?;

    assert_eq!(account.provider_id, "github");
    assert_eq!(account.account_id, "github_ada");
    assert_eq!(account.access_token.as_deref(), Some("access-1"));
    assert_eq!(cookie.attributes.max_age, Some(300));
    Ok(())
}

#[cfg(not(feature = "jose"))]
#[tokio::test]
async fn handle_oauth_user_info_account_cookie_fails_closed_without_jose(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions {
        store_account_cookie: true,
        ..AccountOptions::default()
    })?;

    let result = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("access-1")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await;

    assert!(matches!(
        result,
        Err(openauth_core::error::OpenAuthError::FeatureDisabled { feature: "jose" })
    ));
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_creates_user_account_and_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default())?;

    let result = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("access-1")),
            callback_url: Some("https://app.example.com/callback".to_owned()),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;

    assert!(result.error.is_none());
    assert!(result.is_register);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_respects_signup_and_linking_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default())?;

    let disabled = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", None),
            disable_sign_up: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert_eq!(disabled.error, Some(OAuthUserInfoError::SignupDisabled));

    DbUserStore::new(&adapter)
        .create_user(
            CreateUserInput::new("Ada", "ada@example.com")
                .id("user_1")
                .email_verified(true),
        )
        .await?;
    let rejected = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", false),
            account: oauth_account("github", "github_ada", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert_eq!(rejected.error, Some(OAuthUserInfoError::AccountNotLinked));

    let linked = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("access-2")),
            is_trusted_provider: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(linked.error.is_none());
    assert_eq!(adapter.len("account").await, 1);
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_uses_trusted_provider_configuration_and_disable_implicit_linking(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let trusted_context = test_context(AccountOptions {
        account_linking: AccountLinkingOptions {
            trusted_providers: vec!["github".to_owned()],
            ..AccountLinkingOptions::default()
        },
        ..AccountOptions::default()
    })?;
    DbUserStore::new(&adapter)
        .create_user(CreateUserInput::new("Ada", "ada@example.com").id("user_1"))
        .await?;

    let linked = handle_oauth_user_info(
        &trusted_context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", false),
            account: oauth_account("github", "github_ada", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(linked.error.is_none());
    assert_eq!(adapter.len("account").await, 1);

    let disabled_context = test_context(AccountOptions {
        account_linking: AccountLinkingOptions {
            disable_implicit_linking: true,
            trusted_providers: vec!["google".to_owned()],
            ..AccountLinkingOptions::default()
        },
        ..AccountOptions::default()
    })?;
    DbUserStore::new(&adapter)
        .create_user(CreateUserInput::new("Grace", "grace@example.com").id("user_2"))
        .await?;
    let rejected = handle_oauth_user_info(
        &disabled_context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("google_grace", "grace@example.com", true),
            account: oauth_account("google", "google_grace", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert_eq!(rejected.error, Some(OAuthUserInfoError::AccountNotLinked));

    let new_user = handle_oauth_user_info(
        &disabled_context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("google_new", "new@example.com", true),
            account: oauth_account("google", "google_new", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(new_user.error.is_none());
    assert!(new_user.is_register);
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_uses_provider_scoped_account_lookup(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions {
        account_linking: AccountLinkingOptions {
            trusted_providers: vec!["github".to_owned()],
            ..AccountLinkingOptions::default()
        },
        ..AccountOptions::default()
    })?;

    let google = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("shared_id", "ada@example.com", true),
            account: oauth_account("google", "shared_id", Some("google-access")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(google.error.is_none());

    let github = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("shared_id", "ada@example.com", true),
            account: oauth_account("github", "shared_id", Some("github-access")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(github.error.is_none());
    assert_eq!(adapter.len("account").await, 2);
    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("google".to_owned()))
            && record.get("access_token") == Some(&DbValue::String("google-access".to_owned()))
    }));
    assert!(accounts.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("github".to_owned()))
            && record.get("access_token") == Some(&DbValue::String("github-access".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_respects_update_account_on_sign_in_false(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions {
        update_account_on_sign_in: false,
        ..AccountOptions::default()
    })?;

    handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("old-access")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("new-access")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;

    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(
        |record| record.get("access_token") == Some(&DbValue::String("old-access".to_owned()))
    ));
    assert!(!accounts.iter().any(
        |record| record.get("access_token") == Some(&DbValue::String("new-access".to_owned()))
    ));
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_updates_linked_account_tokens_and_user_info(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default())?;
    let created = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("old-access")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(created.error.is_none());

    let updated = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: OAuthUserInfo {
                name: "Ada Updated".to_owned(),
                image: Some("https://example.com/ada.png".to_owned()),
                ..oauth_user("github_ada", "ada@example.com", true)
            },
            account: oauth_account("github", "github_ada", Some("new-access")),
            override_user_info: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(updated.error.is_none());
    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(
        |record| record.get("access_token") == Some(&DbValue::String("new-access".to_owned()))
    ));
    let users = adapter.records("user").await;
    assert!(users
        .iter()
        .any(|record| record.get("name") == Some(&DbValue::String("Ada Updated".to_owned()))));
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_preserves_linked_account_tokens_when_provider_omits_them(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default())?;
    let created = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: oauth_account("github", "github_ada", Some("old-access")),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(created.error.is_none());

    let updated = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", true),
            account: OAuthAccountInput {
                provider_id: "github".to_owned(),
                account_id: "github_ada".to_owned(),
                scope: Some("profile email".to_owned()),
                ..OAuthAccountInput::default()
            },
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(updated.error.is_none());

    let accounts = adapter.records("account").await;
    let account = accounts
        .iter()
        .find(|record| {
            record.get("provider_id") == Some(&DbValue::String("github".to_owned()))
                && record.get("account_id") == Some(&DbValue::String("github_ada".to_owned()))
        })
        .ok_or("missing linked account")?;
    assert_eq!(
        account.get("access_token"),
        Some(&DbValue::String("old-access".to_owned()))
    );
    assert_eq!(
        account.get("refresh_token"),
        Some(&DbValue::String("refresh".to_owned()))
    );
    assert_eq!(
        account.get("id_token"),
        Some(&DbValue::String("id-token".to_owned()))
    );
    assert_eq!(
        account.get("scope"),
        Some(&DbValue::String("profile email".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_does_not_verify_email_when_provider_email_differs(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default())?;
    let created = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", false),
            account: oauth_account("github", "github_ada", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(created.error.is_none());

    let result = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "other@example.com", true),
            account: oauth_account("github", "github_ada", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;

    let user = result.data.ok_or("missing session user")?.user;
    assert_eq!(user.email, "ada@example.com");
    assert!(!user.email_verified);
    Ok(())
}

#[tokio::test]
async fn handle_oauth_user_info_override_updates_email_and_verified_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let context = test_context(AccountOptions::default())?;
    let created = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: oauth_user("github_ada", "ada@example.com", false),
            account: oauth_account("github", "github_ada", None),
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;
    assert!(created.error.is_none());

    let updated = handle_oauth_user_info(
        &context,
        &adapter,
        HandleOAuthUserInfoInput {
            user_info: OAuthUserInfo {
                name: "Ada Provider".to_owned(),
                email: "ADA.NEW@EXAMPLE.COM".to_owned(),
                email_verified: true,
                image: Some("https://example.com/new.png".to_owned()),
                ..oauth_user("github_ada", "ada-new@example.com", true)
            },
            account: oauth_account("github", "github_ada", None),
            override_user_info: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;

    let user = updated.data.ok_or("missing session user")?.user;
    assert_eq!(user.name, "Ada Provider");
    assert_eq!(user.email, "ada.new@example.com");
    assert!(user.email_verified);
    assert_eq!(user.image.as_deref(), Some("https://example.com/new.png"));
    Ok(())
}

#[test]
fn missing_email_log_message_matches_upstream_guidance() {
    assert!(missing_email_log_message("github", None).contains("Provider \"github\""));
    assert!(missing_email_log_message("generic", Some("generic")).contains("Generic OAuth"));
}

fn test_context(
    account: AccountOptions,
) -> Result<openauth_core::context::AuthContext, openauth_core::error::OpenAuthError> {
    create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        base_url: Some("https://app.example.com".to_owned()),
        account,
        ..OpenAuthOptions::default()
    })
}

fn oauth_user(id: &str, email: &str, email_verified: bool) -> OAuthUserInfo {
    OAuthUserInfo {
        id: id.to_owned(),
        name: "Ada".to_owned(),
        email: email.to_owned(),
        image: None,
        email_verified,
        raw_attributes: None,
    }
}

fn oauth_account(
    provider_id: &str,
    account_id: &str,
    access_token: Option<&str>,
) -> OAuthAccountInput {
    OAuthAccountInput {
        provider_id: provider_id.to_owned(),
        account_id: account_id.to_owned(),
        access_token: access_token.map(str::to_owned),
        refresh_token: Some("refresh".to_owned()),
        id_token: Some("id-token".to_owned()),
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: Some("read:user".to_owned()),
    }
}
