use super::common::{
    cookie_header_from_response, merge_cookie_headers, multi_cookie_name, response_token,
    set_cookie_values, Fixture,
};
use http::{Method, StatusCode};
use rustauth_core::session::DbSessionStore;
use rustauth_plugins::multi_session::MultiSessionOptions;
use serde_json::Value;

#[tokio::test]
async fn sign_in_sets_signed_multi_session_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions::default()).await?;

    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let cookies = set_cookie_values(&response);
    let token = response_token(&response)?;
    let multi_cookie_name = multi_cookie_name(&token);

    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with(&format!("{multi_cookie_name}={token}."))));
    Ok(())
}

#[tokio::test]
async fn sign_up_sets_signed_multi_session_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions::default()).await?;

    let response = fixture.sign_up("new-user@example.com", None).await?;
    let cookies = set_cookie_values(&response);
    let token = response_token(&response)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with(&format!("{}={token}.", multi_cookie_name(&token)))));
    Ok(())
}

#[tokio::test]
async fn latest_sign_in_becomes_active_session() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions::default()).await?;
    let first = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let second = fixture
        .sign_in(
            "grace@example.com",
            "secret123",
            Some(&cookie_header_from_response(&first)),
        )
        .await?;
    let cookie = merge_cookie_headers(&[
        &cookie_header_from_response(&first),
        &cookie_header_from_response(&second),
    ]);

    let response = fixture
        .request(Method::GET, "/api/auth/get-session", "", Some(&cookie))
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["user"]["email"], "grace@example.com");
    Ok(())
}

#[tokio::test]
async fn sign_out_revokes_only_signed_multi_session_cookies(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions::default()).await?;
    let attacker = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let victim = fixture
        .sign_in("grace@example.com", "secret123", None)
        .await?;
    let victim_token = response_token(&victim)?;
    let forged_cookie = format!(
        "{}={victim_token}.fake-signature",
        multi_cookie_name(&victim_token)
    );
    let attacker_cookie = format!(
        "{}; {forged_cookie}",
        cookie_header_from_response(&attacker)
    );

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/sign-out",
            "{}",
            Some(&attacker_cookie),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(DbSessionStore::new(fixture.adapter.as_ref())
        .find_session(&victim_token)
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn sign_out_revokes_valid_multi_session_cookies_and_list_returns_empty(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions::default()).await?;
    let first = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let second = fixture
        .sign_in(
            "grace@example.com",
            "secret123",
            Some(&cookie_header_from_response(&first)),
        )
        .await?;
    let cookie = merge_cookie_headers(&[
        &cookie_header_from_response(&first),
        &cookie_header_from_response(&second),
    ]);

    let sign_out = fixture
        .request(Method::POST, "/api/auth/sign-out", "{}", Some(&cookie))
        .await?;
    let response_cookie = cookie_header_from_response(&sign_out);
    let list = fixture
        .request(
            Method::GET,
            "/api/auth/multi-session/list-device-sessions",
            "",
            Some(&merge_cookie_headers(&[&cookie, &response_cookie])),
        )
        .await?;
    let body: Value = serde_json::from_slice(list.body())?;

    assert_eq!(sign_out.status(), StatusCode::OK);
    assert_eq!(body.as_array().map(Vec::len), Some(0));
    Ok(())
}

#[tokio::test]
async fn same_user_sign_in_replaces_old_multi_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions::default()).await?;
    let first = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let first_token = response_token(&first)?;
    let second = fixture
        .sign_in(
            "ada@example.com",
            "secret123",
            Some(&cookie_header_from_response(&first)),
        )
        .await?;
    let second_token = response_token(&second)?;

    assert_ne!(first_token, second_token);
    assert!(set_cookie_values(&second).iter().any(|cookie| {
        cookie.starts_with(&format!("{}=;", multi_cookie_name(&first_token)))
            && cookie.contains("Max-Age=0")
    }));
    assert!(DbSessionStore::new(fixture.adapter.as_ref())
        .find_session(&first_token)
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn maximum_sessions_prevents_adding_extra_multi_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionOptions {
        maximum_sessions: 1,
    })
    .await?;
    let first = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let second = fixture
        .sign_in(
            "grace@example.com",
            "secret123",
            Some(&cookie_header_from_response(&first)),
        )
        .await?;
    let second_token = response_token(&second)?;

    assert!(!set_cookie_values(&second)
        .iter()
        .any(|cookie| cookie.starts_with(&format!("{}=", multi_cookie_name(&second_token)))));
    Ok(())
}
