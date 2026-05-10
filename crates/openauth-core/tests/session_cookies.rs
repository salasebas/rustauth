use serde::{Deserialize, Serialize};

use openauth_core::cookies::{
    delete_session_cookie, get_cookie_cache, get_cookies, set_cookie_cache, set_session_cookie,
    CookieCachePayload, CookieCacheStrategy, SessionCookieOptions,
};
use openauth_core::crypto::SecretConfig;
use openauth_core::options::{CookieCacheOptions, OpenAuthOptions, SessionOptions};

#[test]
fn set_session_cookie_signs_session_token() -> Result<(), Box<dyn std::error::Error>> {
    let options = OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    };
    let cookies = get_cookies(&options)?;

    let set = set_session_cookie(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        "session-token",
        SessionCookieOptions::default(),
    )?;

    assert_eq!(set[0].name, "better-auth.session_token");
    assert_ne!(set[0].value, "session-token");
    assert!(set[0].value.starts_with("session-token."));
    Ok(())
}

#[test]
fn set_session_cookie_omits_max_age_when_dont_remember_is_true(
) -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;

    let set = set_session_cookie(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        "session-token",
        SessionCookieOptions {
            dont_remember: true,
            ..SessionCookieOptions::default()
        },
    )?;

    let session_cookie = set
        .iter()
        .find(|cookie| cookie.name == "better-auth.session_token")
        .ok_or("session cookie")?;
    let remember_cookie = set
        .iter()
        .find(|cookie| cookie.name == "better-auth.dont_remember")
        .ok_or("remember cookie")?;

    assert_eq!(session_cookie.attributes.max_age, None);
    assert!(remember_cookie.value.starts_with("true."));
    Ok(())
}

#[test]
fn delete_session_cookie_expires_session_cookies_and_chunks(
) -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;

    let expired = delete_session_cookie(
        &cookies,
        "better-auth.session_data.0=abc; better-auth.session_data.1=def",
        false,
    );

    assert!(expired
        .iter()
        .any(|cookie| cookie.name == "better-auth.session_token"));
    assert!(expired
        .iter()
        .any(|cookie| cookie.name == "better-auth.session_data.0"));
    assert!(expired
        .iter()
        .all(|cookie| cookie.attributes.max_age == Some(0)));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestSession {
    token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestUser {
    id: String,
}

#[test]
fn compact_cookie_cache_round_trips_with_valid_signature() -> Result<(), Box<dyn std::error::Error>>
{
    let options = OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        session: SessionOptions {
            cookie_cache: CookieCacheOptions {
                enabled: true,
                version: Some("v1".to_owned()),
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    };
    let cookies = get_cookies(&options)?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Compact,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-a-at-least-32-chars-long!!",
        CookieCacheStrategy::Compact,
        Some("v1"),
    )?;

    assert_eq!(decoded, Some(payload));
    Ok(())
}

#[test]
fn compact_cookie_cache_rejects_tampered_payload() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Compact,
        300,
    )?;
    let mut value = set[0].value.clone();
    value.push('a');
    let header = format!("{}={}", set[0].name, value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-a-at-least-32-chars-long!!",
        CookieCacheStrategy::Compact,
        Some("v1"),
    )?;

    assert_eq!(decoded, None);
    Ok(())
}

#[test]
fn jwt_cookie_cache_round_trips_with_valid_signature() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Jwt,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-a-at-least-32-chars-long!!",
        CookieCacheStrategy::Jwt,
        Some("v1"),
    )?;

    assert_eq!(decoded, Some(payload));
    Ok(())
}

#[test]
fn jwt_cookie_cache_rejects_wrong_secret() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Jwt,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-b-at-least-32-chars-long!!",
        CookieCacheStrategy::Jwt,
        Some("v1"),
    )?;

    assert_eq!(decoded, None);
    Ok(())
}

#[test]
fn jwt_cookie_cache_rejects_version_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Jwt,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-a-at-least-32-chars-long!!",
        CookieCacheStrategy::Jwt,
        Some("v2"),
    )?;

    assert_eq!(decoded, None);
    Ok(())
}

#[test]
fn jwe_cookie_cache_round_trips_with_valid_secret() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Jwe,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-a-at-least-32-chars-long!!",
        CookieCacheStrategy::Jwe,
        Some("v1"),
    )?;

    assert_eq!(decoded, Some(payload));
    Ok(())
}

#[test]
fn jwe_cookie_cache_rejects_wrong_secret() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };

    let set = set_cookie_cache(
        &cookies,
        "secret-a-at-least-32-chars-long!!",
        &payload,
        CookieCacheStrategy::Jwe,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        "secret-b-at-least-32-chars-long!!",
        CookieCacheStrategy::Jwe,
        Some("v1"),
    )?;

    assert_eq!(decoded, None);
    Ok(())
}

#[test]
fn jwe_cookie_cache_decodes_with_rotated_secret_config() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;
    let payload = CookieCachePayload {
        session: TestSession {
            token: "session-token".to_owned(),
        },
        user: TestUser {
            id: "user_123".to_owned(),
        },
        updated_at: 100,
        version: "v1".to_owned(),
    };
    let old_config = SecretConfig::new([(1, "secret-a-at-least-32-chars-long!!")]);
    let rotated_config = SecretConfig::new([
        (2, "secret-b-at-least-32-chars-long!!"),
        (1, "secret-a-at-least-32-chars-long!!"),
    ]);

    let set = set_cookie_cache(
        &cookies,
        &old_config,
        &payload,
        CookieCacheStrategy::Jwe,
        300,
    )?;
    let header = format!("{}={}", set[0].name, set[0].value);
    let decoded = get_cookie_cache::<TestSession, TestUser>(
        &header,
        &cookies.session_data.name,
        &rotated_config,
        CookieCacheStrategy::Jwe,
        Some("v1"),
    )?;

    assert_eq!(decoded, Some(payload));
    Ok(())
}
