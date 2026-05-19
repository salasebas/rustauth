use super::common::{
    cookie_header_from_response, merge_cookie_headers, multi_cookie_name, response_token,
    set_cookie_values, signed_multi_cookie, Fixture,
};
use http::{Method, StatusCode};
use openauth_core::db::{DbFieldType, DbValue};
use openauth_core::options::{
    OpenAuthOptions, SessionAdditionalField, SessionOptions, UserAdditionalField, UserOptions,
};
use openauth_core::session::DbSessionStore;
use openauth_plugins::multi_session::{MultiSessionConfig, INVALID_SESSION_TOKEN};
use serde_json::Value;
use std::collections::BTreeMap;

#[tokio::test]
async fn openapi_metadata_exposes_multi_session_operations(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let openapi = fixture.openapi_schema();

    assert_eq!(
        openapi["paths"]["/multi-session/list-device-sessions"]["get"]["operationId"],
        "listDeviceSessions"
    );
    assert_eq!(
        openapi["paths"]["/multi-session/list-device-sessions"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["type"],
        "array"
    );
    assert_eq!(
        openapi["paths"]["/multi-session/set-active"]["post"]["operationId"],
        "setActiveSession"
    );
    assert_eq!(
        openapi["paths"]["/multi-session/set-active"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["sessionToken"]["type"],
        "string"
    );
    assert_eq!(
        openapi["paths"]["/multi-session/revoke"]["post"]["operationId"],
        "revokeDeviceSession"
    );
    assert_eq!(
        openapi["paths"]["/multi-session/revoke"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["status"]["type"],
        "boolean"
    );
    Ok(())
}

#[tokio::test]
async fn list_device_sessions_returns_valid_unique_user_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let first = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let second_cookie = fixture
        .sign_in(
            "grace@example.com",
            "secret123",
            Some(&cookie_header_from_response(&first)),
        )
        .await?;
    let cookie = merge_cookie_headers(&[
        &cookie_header_from_response(&first),
        &cookie_header_from_response(&second_cookie),
    ]);

    let response = fixture
        .request(
            Method::GET,
            "/api/auth/multi-session/list-device-sessions",
            "",
            Some(&cookie),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body.as_array().map(Vec::len), Some(2));
    assert!(body.as_array().is_some_and(|sessions| sessions
        .iter()
        .any(|item| item["user"]["email"] == "ada@example.com")));
    assert!(body.as_array().is_some_and(|sessions| sessions
        .iter()
        .any(|item| item["user"]["email"] == "grace@example.com")));
    Ok(())
}

#[tokio::test]
async fn list_device_sessions_returns_configured_additional_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture =
        Fixture::with_options(MultiSessionConfig::default(), additional_field_options()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;

    let response = fixture
        .request(
            Method::GET,
            "/api/auth/multi-session/list-device-sessions",
            "",
            Some(&cookie_header_from_response(&response)),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body[0]["user"]["role"], "member");
    assert_eq!(body[0]["session"]["deviceLabel"], "primary");
    Ok(())
}

#[tokio::test]
async fn set_active_accepts_multi_session_cookie_without_active_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let token = response_token(&response)?;
    let cookie = cookie_header_from_response(&response)
        .split("; ")
        .filter(|cookie| !cookie.starts_with("open-auth.session_token="))
        .collect::<Vec<_>>()
        .join("; ");

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn set_active_accepts_normal_active_cookie_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
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
    let first_token = response_token(&first)?;
    let cookie = merge_cookie_headers(&[
        &cookie_header_from_response(&first),
        &cookie_header_from_response(&second),
    ]);

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            &format!(r#"{{"sessionToken":"{first_token}"}}"#),
            Some(&cookie),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn set_active_returns_configured_additional_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture =
        Fixture::with_options(MultiSessionConfig::default(), additional_field_options()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let token = response_token(&response)?;

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie_header_from_response(&response)),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["role"], "member");
    assert_eq!(body["session"]["deviceLabel"], "primary");
    Ok(())
}

#[tokio::test]
async fn set_active_rejects_token_without_signed_multi_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            r#"{"sessionToken":"missing"}"#,
            None,
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], INVALID_SESSION_TOKEN);
    Ok(())
}

#[tokio::test]
async fn set_active_expires_cookie_for_expired_session_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let token = "expired-token";
    fixture.create_expired_session("user_1", token).await?;
    let cookie = signed_multi_cookie(token)?;

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], INVALID_SESSION_TOKEN);
    assert!(set_cookie_values(&response).iter().any(|cookie| {
        cookie.starts_with(&format!("{}=;", multi_cookie_name(token)))
            && cookie.contains("Max-Age=0")
    }));
    Ok(())
}

#[tokio::test]
async fn revoke_deletes_target_session_and_expires_multi_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let token = response_token(&response)?;
    let cookie = cookie_header_from_response(&response);

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/revoke",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(DbSessionStore::new(fixture.adapter.as_ref())
        .find_session(&token)
        .await?
        .is_none());
    assert!(set_cookie_values(&response).iter().any(|cookie| {
        cookie.starts_with(&format!("{}=;", multi_cookie_name(&token)))
            && cookie.contains("Max-Age=0")
    }));
    Ok(())
}

#[tokio::test]
async fn revoke_active_session_sets_next_valid_session_active(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let first = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let first_cookie = cookie_header_from_response(&first);
    let second = fixture
        .sign_in("grace@example.com", "secret123", Some(&first_cookie))
        .await?;
    let second_token = response_token(&second)?;
    let cookie = merge_cookie_headers(&[&first_cookie, &cookie_header_from_response(&second)]);

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/revoke",
            &format!(r#"{{"sessionToken":"{second_token}"}}"#),
            Some(&cookie),
        )
        .await?;
    let promoted_cookie = cookie_header_from_response(&response);
    let session_response = fixture
        .request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&merge_cookie_headers(&[&cookie, &promoted_cookie])),
        )
        .await?;
    let body: Value = serde_json::from_slice(session_response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn revoke_active_session_deletes_active_cookie_when_no_next_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let token = response_token(&response)?;
    let cookie = cookie_header_from_response(&response);

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/revoke",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie),
        )
        .await?;

    assert!(set_cookie_values(&response).iter().any(|cookie| {
        cookie.starts_with("open-auth.session_token=;") && cookie.contains("Max-Age=0")
    }));
    Ok(())
}

#[tokio::test]
async fn forged_multi_session_cookie_is_ignored_by_list() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let token = response_token(&response)?;
    let cookie = format!("{}={token}.fake-signature", multi_cookie_name(&token));

    let response = fixture
        .request(
            Method::GET,
            "/api/auth/multi-session/list-device-sessions",
            "",
            Some(&cookie),
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body.as_array().map(Vec::len), Some(0));
    Ok(())
}

#[tokio::test]
async fn set_active_preserves_dont_remember_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(MultiSessionConfig::default()).await?;
    let response = fixture
        .sign_in_with_body(
            r#"{"email":"ada@example.com","password":"secret123","rememberMe":false}"#,
            None,
        )
        .await?;
    let token = response_token(&response)?;

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie_header_from_response(&response)),
        )
        .await?;
    let cookies = set_cookie_values(&response);
    let active_cookie = cookies
        .iter()
        .find(|cookie| cookie.starts_with("open-auth.session_token="))
        .ok_or("missing active session cookie")?;

    assert!(!active_cookie.contains("Max-Age="));
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.dont_remember=")));
    Ok(())
}

#[tokio::test]
async fn set_active_refreshes_cookie_cache_when_enabled() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::with_cookie_cache(MultiSessionConfig::default()).await?;
    let response = fixture
        .sign_in("ada@example.com", "secret123", None)
        .await?;
    let token = response_token(&response)?;

    let response = fixture
        .request(
            Method::POST,
            "/api/auth/multi-session/set-active",
            &format!(r#"{{"sessionToken":"{token}"}}"#),
            Some(&cookie_header_from_response(&response)),
        )
        .await?;

    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_data=")));
    Ok(())
}

fn additional_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        user: UserOptions {
            additional_fields: BTreeMap::from([(
                "role".to_owned(),
                UserAdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("member".to_owned())),
            )]),
            ..UserOptions::default()
        },
        session: SessionOptions {
            additional_fields: BTreeMap::from([(
                "deviceLabel".to_owned(),
                SessionAdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("primary".to_owned())),
            )]),
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}
