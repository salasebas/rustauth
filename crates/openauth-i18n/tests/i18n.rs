//! Integration tests mirroring Better Auth `i18n.test.ts` scenarios.

mod common;

use std::sync::Arc;

use common::{
    credential_account_record, json_request, json_request_with_headers, router_with_options, user,
    RouteAdapter,
};
use http::Method;
use indexmap::IndexMap;
use openauth_core::api::{create_auth_endpoint, AuthEndpointOptions, AuthRouter};
use openauth_core::auth::email_password::AuthFlowErrorCode;
use openauth_core::context::{create_auth_context, request_state::set_current_session_user};
use openauth_core::crypto::password::hash_password;
use openauth_core::options::OpenAuthOptions;
use openauth_i18n::{
    i18n, translation_dictionary, I18nConfigError, I18nOptions, LocaleDetectionStrategy,
    LocaleResolver,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

fn base_translations() -> IndexMap<String, IndexMap<String, String>> {
    let mut t = IndexMap::new();
    let mut en = IndexMap::new();
    en.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Invalid email or password".into(),
    );
    let mut fr = IndexMap::new();
    fr.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Email ou mot de passe invalide".into(),
    );
    let mut de = IndexMap::new();
    de.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Ungültige E-Mail oder Passwort".into(),
    );
    t.insert("en".into(), en);
    t.insert("fr".into(), fr);
    t.insert("de".into(), de);
    t
}

#[test]
fn translation_dictionary_accepts_typed_core_error_codes() {
    let dictionary = translation_dictionary([(
        AuthFlowErrorCode::InvalidEmailOrPassword,
        "Email ou mot de passe invalide",
    )]);

    assert_eq!(
        dictionary
            .get("INVALID_EMAIL_OR_PASSWORD")
            .map(String::as_str),
        Some("Email ou mot de passe invalide")
    );
}

fn translations_with_locale(
    locale: &str,
    code: &str,
    message: &str,
) -> IndexMap<String, IndexMap<String, String>> {
    let mut translations = IndexMap::new();
    let mut dictionary = IndexMap::new();
    dictionary.insert(code.to_owned(), message.to_owned());
    translations.insert(locale.to_owned(), dictionary);
    translations
}

fn test_router_with_error_response(
    opts: I18nOptions,
    status: http::StatusCode,
    body: Value,
    headers: &[(&str, &str)],
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let mut builder = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json");
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    let response = builder.body(serde_json::to_vec(&body)?)?;
    let endpoint = create_auth_endpoint(
        "/custom-error",
        Method::GET,
        AuthEndpointOptions::new(),
        move |_context, _request| {
            let response = response.clone();
            Box::pin(async move { Ok(response) })
        },
    );
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        plugins: vec![i18n(opts)?],
        ..OpenAuthOptions::default()
    })?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        vec![endpoint],
    )?)
}

fn empty_get_request(
    path: &str,
    headers: &[(&str, &str)],
) -> Result<http::Request<Vec<u8>>, http::Error> {
    let mut builder = http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://localhost:3000{path}"));
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    builder.body(Vec::new())
}

// Header detection.

#[tokio::test]
async fn translates_invalid_sign_in_for_accept_language_fr(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Header,
        LocaleDetectionStrategy::Cookie,
    ];

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "fr")],
            None,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_EMAIL_OR_PASSWORD");
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    assert_eq!(body["originalMessage"], "Invalid email or password");
    Ok(())
}

#[tokio::test]
async fn translates_for_accept_language_de() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Header];

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn falls_back_to_default_when_locale_not_in_catalog() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "es")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Invalid email or password");
    Ok(())
}

#[tokio::test]
async fn accept_language_quality_prefers_first_available() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "es;q=0.9, fr;q=0.8, en;q=0.7")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

#[tokio::test]
async fn accept_language_region_maps_to_base_locale() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "fr-CA")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

// Cookie detection.

#[tokio::test]
async fn cookie_beats_header_when_ordered_first() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Cookie,
        LocaleDetectionStrategy::Header,
    ];
    opts.locale_cookie = "lang".into();

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            Some("lang=fr"),
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

#[tokio::test]
async fn cookie_values_containing_equals_are_supported() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut translations = base_translations();
    translations.insert("fr=CA".into(), {
        let mut dictionary = IndexMap::new();
        dictionary.insert(
            "INVALID_EMAIL_OR_PASSWORD".into(),
            "Courriel ou mot de passe invalide".into(),
        );
        dictionary
    });
    let mut opts = I18nOptions::new(translations);
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Cookie];
    opts.locale_cookie = "lang".into();

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            Some("lang=fr=CA"),
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Courriel ou mot de passe invalide");
    Ok(())
}

#[tokio::test]
async fn cookie_strategy_falls_through_when_cookie_missing_or_unsupported(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Cookie,
        LocaleDetectionStrategy::Header,
    ];
    opts.locale_cookie = "lang".into();

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            Some("lang=es"),
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn cookie_strategy_falls_through_when_cookie_is_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Cookie,
        LocaleDetectionStrategy::Header,
    ];
    opts.locale_cookie = "lang".into();

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

// Callback detection.

#[tokio::test]
async fn callback_custom_header_locale() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Callback];
    let resolver: LocaleResolver = Arc::new(|_ctx, req| {
        req.headers()
            .get("x-custom-locale")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    });
    opts.get_locale = Some(resolver);

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("X-Custom-Locale", "fr")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

// Session detection.

#[tokio::test]
async fn session_resolver_locale_is_used_when_session_detection_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Session];
    opts.resolve_user_locale = Some(Arc::new(|_ctx, _req| Some("fr".into())));

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

#[tokio::test]
async fn session_detection_reads_user_locale_field_from_request_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut translations = base_translations();
    translations.insert("ada@example.com".into(), {
        let mut dictionary = IndexMap::new();
        dictionary.insert(
            "CURRENT_SESSION_ERROR".into(),
            "Message depuis la session".into(),
        );
        dictionary
    });
    let mut opts = I18nOptions::new(translations);
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Session];
    opts.user_locale_field = "email".into();

    let endpoint = create_auth_endpoint(
        "/session-error",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| {
            Box::pin(async move {
                set_current_session_user(json!({
                    "email": "ada@example.com",
                    "locale": "fr"
                }))?;
                http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(
                        serde_json::to_vec(&json!({
                            "code": "CURRENT_SESSION_ERROR",
                            "message": "Original message"
                        }))
                        .map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(error.to_string())
                        })?,
                    )
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))
            })
        },
    );
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        plugins: vec![i18n(opts)?],
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), vec![endpoint])?;

    let response = router
        .handle_async(empty_get_request("/api/auth/session-error", &[])?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["message"], "Message depuis la session");
    Ok(())
}

#[tokio::test]
async fn session_resolver_falls_through_when_absent_or_unsupported(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Session,
        LocaleDetectionStrategy::Header,
    ];
    opts.resolve_user_locale = Some(Arc::new(|_ctx, _req| Some("es".into())));

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn session_resolver_falls_through_when_it_returns_none(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Session,
        LocaleDetectionStrategy::Header,
    ];
    opts.resolve_user_locale = Some(Arc::new(|_ctx, _req| None));

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn session_detection_falls_through_when_no_session_user_is_in_request_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Session,
        LocaleDetectionStrategy::Header,
    ];

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn callback_constant_locale_without_headers() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Callback];
    opts.get_locale = Some(Arc::new(|_ctx, _req| Some("fr".into())));

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

#[tokio::test]
async fn callback_falls_through_when_none_or_unsupported() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Callback,
        LocaleDetectionStrategy::Header,
    ];
    opts.get_locale = Some(Arc::new(|_ctx, _req| Some("es".into())));

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn callback_falls_through_when_it_returns_none() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Callback,
        LocaleDetectionStrategy::Header,
    ];
    opts.get_locale = Some(Arc::new(|_ctx, _req| None));

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            &[("Accept-Language", "de")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

// Fallback and validation.

#[tokio::test]
async fn default_locale_first_inserted_when_no_en() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut t = IndexMap::new();
    let mut fr = IndexMap::new();
    fr.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Email ou mot de passe invalide".into(),
    );
    let mut de = IndexMap::new();
    de.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Ungültige E-Mail oder Passwort".into(),
    );
    t.insert("fr".into(), fr);
    t.insert("de".into(), de);

    let opts = I18nOptions::new(t);
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    Ok(())
}

#[tokio::test]
async fn explicit_default_locale_de() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut fr = IndexMap::new();
    fr.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Email ou mot de passe invalide".into(),
    );
    let mut de = IndexMap::new();
    de.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Ungültige E-Mail oder Passwort".into(),
    );
    let mut t = IndexMap::new();
    t.insert("fr".into(), fr);
    t.insert("de".into(), de);

    let mut opts = I18nOptions::new(t);
    opts.default_locale = Some("de".into());

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Ungültige E-Mail oder Passwort");
    Ok(())
}

#[tokio::test]
async fn implicit_default_en_when_present() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut de = IndexMap::new();
    de.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Ungültige E-Mail oder Passwort".into(),
    );
    let mut en = IndexMap::new();
    en.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Invalid email or password".into(),
    );
    let mut fr = IndexMap::new();
    fr.insert(
        "INVALID_EMAIL_OR_PASSWORD".into(),
        "Email ou mot de passe invalide".into(),
    );
    let mut t = IndexMap::new();
    t.insert("de".into(), de);
    t.insert("en".into(), en);
    t.insert("fr".into(), fr);

    let opts = I18nOptions::new(t);
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrongpassword"}"#,
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Invalid email or password");
    Ok(())
}

#[tokio::test]
async fn successful_sign_in_body_not_modified() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;

    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("en".into());

    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            &[("Accept-Language", "fr")],
            None,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.get("user").is_some());
    Ok(())
}

#[test]
fn empty_translations_rejected() {
    assert!(matches!(
        i18n(I18nOptions::new(IndexMap::new())),
        Err(I18nConfigError::EmptyTranslations)
    ));
}

#[test]
fn unknown_default_locale_rejected() {
    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("es".into());

    assert!(matches!(
        i18n(opts),
        Err(I18nConfigError::UnknownDefaultLocale(locale)) if locale == "es"
    ));
}

#[test]
fn detection_strategy_deserialization_rejects_unknown_values() {
    let parsed = serde_json::from_str::<LocaleDetectionStrategy>(r#""browser""#);

    assert!(parsed.is_err());
}

#[test]
fn options_default_user_locale_field_is_locale() {
    let opts = I18nOptions::new(base_translations());

    assert_eq!(opts.user_locale_field, "locale");
}

#[test]
fn plugin_exposes_resolved_serializable_options_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let mut opts = I18nOptions::new(base_translations());
    opts.default_locale = Some("fr".into());
    opts.detection = vec![
        LocaleDetectionStrategy::Cookie,
        LocaleDetectionStrategy::Header,
    ];
    opts.locale_cookie = "lang".into();
    opts.user_locale_field = "preferred_locale".into();

    let plugin = i18n(opts)?;
    let metadata = plugin
        .options
        .as_ref()
        .ok_or("missing i18n options metadata")?;

    assert_eq!(metadata["defaultLocale"], "fr");
    assert_eq!(metadata["detection"], json!(["cookie", "header"]));
    assert_eq!(metadata["localeCookie"], "lang");
    assert_eq!(metadata["userLocaleField"], "preferred_locale");
    Ok(())
}

// Error response shape.

#[tokio::test]
async fn missing_translation_leaves_error_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = I18nOptions::new(translations_with_locale(
        "fr",
        "OTHER_CODE",
        "Autre message",
    ));
    opts.default_locale = Some("fr".into());

    let router = test_router_with_error_response(
        opts,
        http::StatusCode::BAD_REQUEST,
        json!({
            "code": "MISSING_TRANSLATION",
            "message": "Original message"
        }),
        &[],
    )?;

    let response = router
        .handle_async(empty_get_request(
            "/api/auth/custom-error",
            &[("Accept-Language", "fr")],
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["message"], "Original message");
    assert!(body.get("originalMessage").is_none());
    Ok(())
}

#[tokio::test]
async fn non_string_error_code_leaves_error_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = I18nOptions::new(translations_with_locale("fr", "123", "Message traduit"));
    opts.default_locale = Some("fr".into());

    let router = test_router_with_error_response(
        opts,
        http::StatusCode::BAD_REQUEST,
        json!({
            "code": 123,
            "message": "Original message"
        }),
        &[],
    )?;

    let response = router
        .handle_async(empty_get_request(
            "/api/auth/custom-error",
            &[("Accept-Language", "fr")],
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["code"], 123);
    assert_eq!(body["message"], "Original message");
    Ok(())
}

#[tokio::test]
async fn translated_response_preserves_original_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let mut opts = I18nOptions::new(translations_with_locale(
        "fr",
        "NEEDS_HEADER",
        "Message traduit",
    ));
    opts.default_locale = Some("fr".into());

    let router = test_router_with_error_response(
        opts,
        http::StatusCode::BAD_REQUEST,
        json!({
            "code": "NEEDS_HEADER",
            "message": "Original message"
        }),
        &[("X-Custom-Error", "kept")],
    )?;

    let response = router
        .handle_async(empty_get_request(
            "/api/auth/custom-error",
            &[("Accept-Language", "fr")],
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["message"], "Message traduit");
    assert_eq!(
        response
            .headers()
            .get("x-custom-error")
            .and_then(|v| v.to_str().ok()),
        Some("kept")
    );
    Ok(())
}
