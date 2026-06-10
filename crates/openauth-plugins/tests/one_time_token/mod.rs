mod helpers;

use helpers::*;
use http::{header, Method, StatusCode};
use openauth_core::db::{DbAdapter, DbFieldType, DbValue, Update, Where};
use openauth_core::options::{
    CookieCacheOptions, OpenAuthOptions, SessionAdditionalField, SessionOptions,
    UserAdditionalField, UserOptions,
};
use openauth_plugins::one_time_token::{
    default_key_hasher, one_time_token, one_time_token_with, OneTimeTokenOptions, StoreToken,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn registers_generate_and_verify_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = router_with_plugin(one_time_token())?;
    let registry = router.endpoint_registry();

    assert!(registry.iter().any(|endpoint| {
        endpoint.path == "/one-time-token/generate" && endpoint.method == Method::GET
    }));
    assert!(registry.iter().any(|endpoint| {
        endpoint.path == "/one-time-token/verify" && endpoint.method == Method::POST
    }));
    Ok(())
}

#[tokio::test]
async fn endpoints_expose_openapi_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = router_with_plugin(one_time_token())?;
    let openapi = router.openapi_schema();

    assert_eq!(
        openapi["paths"]["/one-time-token/generate"]["get"]["operationId"],
        "generateOneTimeToken"
    );
    assert_eq!(
        openapi["paths"]["/one-time-token/generate"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["token"]["type"],
        "string"
    );
    assert_eq!(
        openapi["paths"]["/one-time-token/verify"]["post"]["operationId"],
        "verifyOneTimeToken"
    );
    assert_eq!(
        openapi["paths"]["/one-time-token/verify"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["token"]["type"],
        "string"
    );
    assert_eq!(
        openapi["paths"]["/one-time-token/verify"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["session"]["$ref"],
        "#/components/schemas/Session"
    );
    Ok(())
}

#[test]
fn plugin_options_metadata_uses_upstream_camel_case_names() -> Result<(), Box<dyn std::error::Error>>
{
    let plugin = one_time_token_with(
        OneTimeTokenOptions::default()
            .expires_in_minutes(10)
            .disable_client_request(true)
            .disable_set_session_cookie(true)
            .store_token(StoreToken::Hashed)
            .set_ott_header_on_new_session(true),
    );
    let options = plugin
        .options
        .ok_or("plugin options should be serialized")?;

    assert_eq!(options["expiresIn"], 10);
    assert_eq!(options["disableClientRequest"], true);
    assert_eq!(options["disableSetSessionCookie"], true);
    assert_eq!(options["storeToken"], "hashed");
    assert_eq!(options["setOttHeaderOnNewSession"], true);
    Ok(())
}

#[tokio::test]
async fn concurrent_verify_allows_only_one_redemption() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_plugin(one_time_token())?;
    seed_user_and_session(&adapter, default_session_expires_at()).await?;
    seed_verification(
        &adapter,
        "one-time-token:race-token",
        "session-token",
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await?;

    let (first, second) = tokio::join!(
        router.handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"race-token"}"#,
            None,
        )?),
        router.handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"race-token"}"#,
            None,
        )?),
    );
    let responses = [first?, second?];
    let ok = responses
        .iter()
        .filter(|response| response.status() == StatusCode::OK)
        .count();
    let invalid = responses
        .iter()
        .filter(|response| response.status() == StatusCode::BAD_REQUEST)
        .count();

    assert_eq!(ok, 1, "only one concurrent verify should redeem the token");
    assert_eq!(
        invalid, 1,
        "the losing concurrent verify should observe an invalid token"
    );
    Ok(())
}

#[tokio::test]
async fn generated_token_verifies_once_and_sets_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_plugin(one_time_token())?;
    let cookie = seed_authenticated_session(&adapter, default_session_expires_at()).await?;

    let generate = router
        .handle_async(request(
            Method::GET,
            "/api/auth/one-time-token/generate",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(generate.status(), StatusCode::OK);
    let generated: Value = serde_json::from_slice(generate.body())?;
    let token = generated["token"]
        .as_str()
        .ok_or("missing generated token")?;

    let verify = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            &format!(r#"{{"token":"{token}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(verify.status(), StatusCode::OK);
    let verified: Value = serde_json::from_slice(verify.body())?;
    assert_eq!(verified["session"]["token"], "session-token");
    assert_eq!(verified["user"]["email"], "ada@example.com");
    assert!(set_cookie_values(&verify)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            &format!(r#"{{"token":"{token}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let second_body: Value = serde_json::from_slice(second.body())?;
    assert_eq!(second_body["message"], "Invalid token");
    Ok(())
}

#[tokio::test]
async fn generated_token_expires_after_configured_ttl() -> Result<(), Box<dyn std::error::Error>> {
    let options = OneTimeTokenOptions::default()
        .expires_in_minutes(5)
        .generate_token(|_, _| Ok("ttl-token".to_owned()));
    let (adapter, router) = router_with_plugin(one_time_token_with(options))?;
    let cookie = seed_authenticated_session(&adapter, default_session_expires_at()).await?;

    let generate = router
        .handle_async(request(
            Method::GET,
            "/api/auth/one-time-token/generate",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(generate.status(), StatusCode::OK);
    let generated: Value = serde_json::from_slice(generate.body())?;
    assert_eq!(generated["token"].as_str(), Some("ttl-token"));

    let record = verification_record(&adapter, "one-time-token:ttl-token")
        .await?
        .ok_or("missing generated verification record")?;
    let expires_at = match record.get("expires_at") {
        Some(DbValue::Timestamp(value)) => *value,
        _ => return Err("verification expires_at should be a timestamp".into()),
    };
    let now = OffsetDateTime::now_utc();
    assert!(expires_at >= now + Duration::minutes(4));
    assert!(expires_at <= now + Duration::minutes(6));

    adapter
        .update(
            Update::new("verification")
                .where_clause(Where::new(
                    "identifier",
                    DbValue::String("one-time-token:ttl-token".to_owned()),
                ))
                .data(
                    "expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::minutes(1)),
                ),
        )
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"ttl-token"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Token expired");
    Ok(())
}

#[tokio::test]
async fn verify_returns_configured_additional_fields() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_plugin_and_options(one_time_token(), additional_field_options())?;
    seed_user_and_session(&adapter, default_session_expires_at()).await?;
    seed_verification(
        &adapter,
        "one-time-token:valid-token",
        "session-token",
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"valid-token"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["role"], "member");
    assert_eq!(body["session"]["deviceLabel"], "primary");
    Ok(())
}

#[tokio::test]
async fn verify_sets_cookie_cache_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let options = OpenAuthOptions {
        session: SessionOptions {
            cookie_cache: CookieCacheOptions {
                enabled: true,
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    };
    let (adapter, router) = router_with_plugin_and_options(one_time_token(), options)?;
    seed_user_and_session(&adapter, default_session_expires_at()).await?;
    seed_verification(
        &adapter,
        "one-time-token:cache-token",
        "session-token",
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"cache-token"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_data=")));
    Ok(())
}

#[tokio::test]
async fn generate_preserves_refresh_cookies_from_session_lookup(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OpenAuthOptions {
        session: SessionOptions {
            expires_in: Some(60 * 60 * 24),
            update_age: Some(0),
            cookie_cache: CookieCacheOptions {
                enabled: true,
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    };
    let cookie = signed_session_cookie_with_options("session-token", options.clone())?;
    let (adapter, router) = router_with_plugin_and_options(one_time_token(), options)?;
    seed_user_and_session(&adapter, OffsetDateTime::now_utc() + Duration::hours(1)).await?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/one-time-token/generate",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_data=")));
    Ok(())
}

#[tokio::test]
async fn expired_token_fails_and_is_consumed() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_plugin(one_time_token())?;
    seed_user_and_session(&adapter, default_session_expires_at()).await?;
    seed_verification(
        &adapter,
        "one-time-token:expired-token",
        "session-token",
        OffsetDateTime::now_utc() - Duration::minutes(1),
    )
    .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"expired-token"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Token expired");
    assert!(
        verification_record(&adapter, "one-time-token:expired-token")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn expired_session_fails_with_session_expired() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_plugin(one_time_token_with(
        OneTimeTokenOptions::default().expires_in_minutes(10),
    ))?;
    seed_user_and_session(&adapter, OffsetDateTime::now_utc() - Duration::minutes(1)).await?;
    seed_verification(
        &adapter,
        "one-time-token:valid-token",
        "session-token",
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"valid-token"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Session expired");
    Ok(())
}

#[tokio::test]
async fn hashed_storage_uses_default_key_hasher() -> Result<(), Box<dyn std::error::Error>> {
    let options = OneTimeTokenOptions::default()
        .store_token(StoreToken::Hashed)
        .generate_token(|_, _| Ok("123456".to_owned()));
    let (adapter, router) = router_with_plugin(one_time_token_with(options))?;
    let cookie = seed_authenticated_session(&adapter, default_session_expires_at()).await?;

    let generate = router
        .handle_async(request(
            Method::GET,
            "/api/auth/one-time-token/generate",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(generate.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(generate.body())?;
    assert_eq!(body["token"], "123456");
    let hashed = default_key_hasher("123456");
    assert!(
        verification_record(&adapter, &format!("one-time-token:{hashed}"))
            .await?
            .is_some()
    );
    assert!(verification_record(&adapter, "one-time-token:123456")
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn custom_storage_hasher_is_used() -> Result<(), Box<dyn std::error::Error>> {
    let options = OneTimeTokenOptions::default()
        .store_token(StoreToken::custom(|token| Ok(format!("{token}:hashed"))))
        .generate_token(|_, _| Ok("custom-token".to_owned()));
    let (adapter, router) = router_with_plugin(one_time_token_with(options))?;
    let cookie = seed_authenticated_session(&adapter, default_session_expires_at()).await?;

    let generate = router
        .handle_async(request(
            Method::GET,
            "/api/auth/one-time-token/generate",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(generate.status(), StatusCode::OK);
    assert!(
        verification_record(&adapter, "one-time-token:custom-token:hashed")
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn disable_set_session_cookie_omits_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let options = OneTimeTokenOptions::default().disable_set_session_cookie(true);
    let (adapter, router) = router_with_plugin(one_time_token_with(options))?;
    seed_user_and_session(&adapter, default_session_expires_at()).await?;
    seed_verification(
        &adapter,
        "one-time-token:no-cookie-token",
        "session-token",
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/one-time-token/verify",
            r#"{"token":"no-cookie-token"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookie_values(&response).is_empty());
    Ok(())
}

#[tokio::test]
async fn disable_client_request_rejects_generate_endpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let options = OneTimeTokenOptions::default().disable_client_request(true);
    let (adapter, router) = router_with_plugin(one_time_token_with(options))?;
    let cookie = seed_authenticated_session(&adapter, default_session_expires_at()).await?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/one-time-token/generate",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Client requests are disabled");
    Ok(())
}

#[tokio::test]
async fn set_ott_header_on_new_sign_up_session() -> Result<(), Box<dyn std::error::Error>> {
    let options = OneTimeTokenOptions::default().set_ott_header_on_new_session(true);
    let (_adapter, router) = router_with_plugin(one_time_token_with(options))?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let ott = response
        .headers()
        .get("set-ott")
        .and_then(|value| value.to_str().ok())
        .ok_or("missing set-ott header")?;
    assert_eq!(ott.len(), 32);
    assert!(response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|header| header.trim() == "set-ott")));
    Ok(())
}

#[tokio::test]
async fn set_ott_header_on_new_sign_in_session() -> Result<(), Box<dyn std::error::Error>> {
    let options = OneTimeTokenOptions::default().set_ott_header_on_new_session(true);
    let (adapter, router) = router_with_plugin(one_time_token_with(options))?;
    seed_user_and_credential_account(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-ott").is_some());
    Ok(())
}

fn additional_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        user: UserOptions {
            additional_fields: std::collections::BTreeMap::from([(
                "role".to_owned(),
                UserAdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("member".to_owned())),
            )]),
            ..UserOptions::default()
        },
        session: SessionOptions {
            additional_fields: std::collections::BTreeMap::from([(
                "deviceLabel".to_owned(),
                SessionAdditionalField::new(DbFieldType::String)
                    .default_value(DbValue::String("primary".to_owned())),
            )]),
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}
