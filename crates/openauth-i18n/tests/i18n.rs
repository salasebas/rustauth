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
use openauth_core::options::OpenAuthOptions;
use openauth_core::test_utils::fast_hash_password;
use openauth_i18n::{
    i18n, translation_dictionary, AsyncLocaleResolver, I18nConfigError, I18nOptions,
    LocaleDetectionStrategy, LocaleResolver,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

fn base_options() -> I18nOptions {
    I18nOptions::new()
        .locale(
            "en",
            [("INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")],
        )
        .locale(
            "fr",
            [(
                "INVALID_EMAIL_OR_PASSWORD",
                "Email ou mot de passe invalide",
            )],
        )
        .locale(
            "de",
            [(
                "INVALID_EMAIL_OR_PASSWORD",
                "Ungültige E-Mail oder Passwort",
            )],
        )
}

fn base_translations() -> IndexMap<String, IndexMap<String, String>> {
    base_options().translations
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

fn options_with_locale(locale: &str, code: &str, message: &str) -> I18nOptions {
    I18nOptions::new().locale(locale, [(code, message)])
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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

#[tokio::test]
async fn accept_language_prefers_exact_region_before_base_locale(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut translations = base_translations();
    translations.insert("pt".into(), {
        let mut dictionary = IndexMap::new();
        dictionary.insert(
            "INVALID_EMAIL_OR_PASSWORD".into(),
            "Email ou senha inválidos".into(),
        );
        dictionary
    });
    translations.insert("pt-BR".into(), {
        let mut dictionary = IndexMap::new();
        dictionary.insert(
            "INVALID_EMAIL_OR_PASSWORD".into(),
            "E-mail ou senha inválidos".into(),
        );
        dictionary
    });
    let mut opts = I18nOptions::from_translations(translations);
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
            &[("Accept-Language", "pt-BR, pt;q=0.9")],
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "E-mail ou senha inválidos");
    Ok(())
}

#[tokio::test]
async fn accept_language_matches_locale_case_insensitively(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &[("Accept-Language", "FR-ca")],
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
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
    let mut opts = I18nOptions::from_translations(translations);
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
    let mut opts = I18nOptions::from_translations(translations);
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
async fn session_detection_reads_default_locale_field() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = base_options();
    opts.default_locale = Some("en".into());
    opts.detection = vec![LocaleDetectionStrategy::Session];

    let endpoint = create_auth_endpoint(
        "/session-locale-error",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| {
            Box::pin(async move {
                set_current_session_user(json!({
                    "id": "user_1",
                    "locale": "fr"
                }))?;
                http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(
                        serde_json::to_vec(&json!({
                            "code": "INVALID_EMAIL_OR_PASSWORD",
                            "message": "Invalid email or password"
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
        .handle_async(empty_get_request("/api/auth/session-locale-error", &[])?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["message"], "Email ou mot de passe invalide");
    assert_eq!(body["originalMessage"], "Invalid email or password");
    Ok(())
}

#[tokio::test]
async fn translates_not_found_on_early_router_exit() -> Result<(), Box<dyn std::error::Error>> {
    let mut translations = IndexMap::new();
    translations.insert(
        "en".into(),
        translation_dictionary([("NOT_FOUND", "Introuvable")]),
    );
    let opts = I18nOptions::from_translations(translations).default_locale("en");

    let context = create_auth_context(OpenAuthOptions {
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        plugins: vec![i18n(opts)?],
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), Vec::new())?;

    let response = router
        .handle_async(
            http::Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/does-not-exist")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "NOT_FOUND");
    assert_eq!(body["message"], "Introuvable");
    assert_eq!(body["originalMessage"], "Not Found");
    Ok(())
}

#[tokio::test]
async fn translates_rate_limit_on_early_router_exit() -> Result<(), Box<dyn std::error::Error>> {
    use openauth_core::options::{RateLimitOptions, RateLimitPathRule, RateLimitRule};

    let mut translations = IndexMap::new();
    translations.insert(
        "en".into(),
        translation_dictionary([("TOO_MANY_REQUESTS", "Trop de requêtes, réessayez plus tard")]),
    );
    let opts = I18nOptions::from_translations(translations).default_locale("en");

    let endpoint = create_auth_endpoint(
        "/limited",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| {
            Box::pin(async move {
                http::Response::builder()
                    .status(http::StatusCode::OK)
                    .body(Vec::new())
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))
            })
        },
    );
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        plugins: vec![i18n(opts)?],
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            custom_rules: vec![RateLimitPathRule {
                path: "/limited".to_owned(),
                rule: Some(RateLimitRule { window: 60, max: 1 }),
            }],
            ..RateLimitOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), vec![endpoint])?;

    let first = router
        .handle_async(empty_get_request("/api/auth/limited", &[])?)
        .await?;
    assert_eq!(first.status(), http::StatusCode::OK);

    let second = router
        .handle_async(empty_get_request("/api/auth/limited", &[])?)
        .await?;
    assert_eq!(second.status(), http::StatusCode::TOO_MANY_REQUESTS);
    let body: Value = serde_json::from_slice(second.body())?;
    assert_eq!(body["code"], "TOO_MANY_REQUESTS");
    assert_eq!(body["message"], "Trop de requêtes, réessayez plus tard");
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
async fn async_callback_constant_locale_without_headers() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let resolver: AsyncLocaleResolver =
        Arc::new(|_ctx, _req| Box::pin(async { Some("fr".into()) }));
    let opts = base_options()
        .default_locale("en")
        .detection([LocaleDetectionStrategy::Callback])
        .get_locale_async(resolver);

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
    assert_eq!(body["code"], "INVALID_EMAIL_OR_PASSWORD");
    assert_eq!(body["message"], "Email ou mot de passe invalide");
    assert_eq!(body["originalMessage"], "Invalid email or password");
    Ok(())
}

#[tokio::test]
async fn async_callback_custom_header_locale() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let resolver: AsyncLocaleResolver = Arc::new(|_ctx, req| {
        let locale = req
            .headers()
            .get("x-custom-locale")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Box::pin(async move { locale })
    });
    let opts = base_options()
        .default_locale("en")
        .detection([LocaleDetectionStrategy::Callback])
        .get_locale_async(resolver);

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

#[tokio::test]
async fn callback_falls_through_when_none_or_unsupported() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
            &fast_hash_password("other-password")?,
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

    let opts = I18nOptions::from_translations(t);
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
            &fast_hash_password("other-password")?,
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

    let mut opts = I18nOptions::from_translations(t);
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
            &fast_hash_password("other-password")?,
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

    let opts = I18nOptions::from_translations(t);
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
            &fast_hash_password("secret123")?,
            now,
        ))
        .await?;

    let mut opts = base_options();
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
        i18n(I18nOptions::new()),
        Err(I18nConfigError::EmptyTranslations)
    ));
}

#[test]
fn unknown_default_locale_rejected() {
    let mut opts = base_options();
    opts.default_locale = Some("es".into());

    assert!(matches!(
        i18n(opts),
        Err(I18nConfigError::UnknownDefaultLocale(locale)) if locale == "es"
    ));
}

#[test]
fn duplicate_locales_after_normalization_are_rejected() {
    let mut translations = base_translations();
    translations.insert("EN".into(), translation_dictionary([("OTHER", "Other")]));

    assert!(matches!(
        i18n(I18nOptions::from_translations(translations)),
        Err(I18nConfigError::DuplicateLocale(locale)) if locale == "EN"
    ));
}

#[test]
fn empty_locale_cookie_is_rejected_when_cookie_detection_is_enabled() {
    let mut opts = base_options();
    opts.detection = vec![LocaleDetectionStrategy::Cookie];
    opts.locale_cookie.clear();

    assert!(matches!(
        i18n(opts),
        Err(I18nConfigError::EmptyLocaleCookie)
    ));
}

#[test]
fn empty_user_locale_field_is_rejected_when_session_detection_is_enabled() {
    let mut opts = base_options();
    opts.detection = vec![LocaleDetectionStrategy::Session];
    opts.user_locale_field.clear();

    assert!(matches!(
        i18n(opts),
        Err(I18nConfigError::EmptyUserLocaleField)
    ));
}

#[test]
fn options_builder_methods_configure_public_options() {
    let opts = base_options()
        .default_locale("fr")
        .detection([
            LocaleDetectionStrategy::Cookie,
            LocaleDetectionStrategy::Header,
        ])
        .locale_cookie("lang")
        .user_locale_field("preferred_locale")
        .get_locale(Arc::new(|_ctx, _req| Some("fr".to_owned())))
        .resolve_user_locale(Arc::new(|_ctx, _req| Some("de".to_owned())));

    assert_eq!(opts.default_locale.as_deref(), Some("fr"));
    assert_eq!(
        opts.detection,
        vec![
            LocaleDetectionStrategy::Cookie,
            LocaleDetectionStrategy::Header
        ]
    );
    assert_eq!(opts.locale_cookie, "lang");
    assert_eq!(opts.user_locale_field, "preferred_locale");
    assert!(opts.get_locale.is_some());
    assert!(opts.resolve_user_locale.is_some());
}

#[test]
fn options_debug_hides_callback_internals() {
    let opts = base_options().get_locale(Arc::new(|_ctx, _req| Some("fr".to_owned())));

    assert!(format!("{opts:?}").contains("<locale-resolver>"));
}

#[test]
fn detection_strategy_deserialization_rejects_unknown_values() {
    let parsed = serde_json::from_str::<LocaleDetectionStrategy>(r#""browser""#);

    assert!(parsed.is_err());
}

#[test]
fn options_default_user_locale_field_is_locale() {
    let opts = base_options();

    assert_eq!(opts.user_locale_field, "locale");
}

#[test]
fn plugin_exposes_resolved_serializable_options_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let mut opts = base_options();
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
    let mut opts = options_with_locale("fr", "OTHER_CODE", "Autre message");
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
    let mut opts = options_with_locale("fr", "123", "Message traduit");
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
    let mut opts = options_with_locale("fr", "NEEDS_HEADER", "Message traduit");
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

#[tokio::test]
async fn translated_response_removes_stale_content_length() -> Result<(), Box<dyn std::error::Error>>
{
    let mut opts = options_with_locale("fr", "NEEDS_HEADER", "Message traduit");
    opts.default_locale = Some("fr".into());

    let router = test_router_with_error_response(
        opts,
        http::StatusCode::BAD_REQUEST,
        json!({
            "code": "NEEDS_HEADER",
            "message": "Original message"
        }),
        &[("Content-Length", "999")],
    )?;

    let response = router
        .handle_async(empty_get_request(
            "/api/auth/custom-error",
            &[("Accept-Language", "fr")],
        )?)
        .await?;

    assert!(response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .is_none());
    Ok(())
}

#[tokio::test]
async fn text_plain_response_is_not_translated() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = options_with_locale("fr", "NEEDS_HEADER", "Message traduit");
    opts.default_locale = Some("fr".into());

    let response = http::Response::builder()
        .status(http::StatusCode::BAD_REQUEST)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .body(serde_json::to_vec(&json!({
            "code": "NEEDS_HEADER",
            "message": "Original message"
        }))?)?;
    let endpoint = create_auth_endpoint(
        "/plain-error",
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
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), vec![endpoint])?;

    let response = router
        .handle_async(empty_get_request(
            "/api/auth/plain-error",
            &[("Accept-Language", "fr")],
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["message"], "Original message");
    assert!(body.get("originalMessage").is_none());
    Ok(())
}

#[tokio::test]
async fn arbitrary_json_with_code_and_message_is_not_translated(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = options_with_locale("fr", "NEEDS_HEADER", "Message traduit");
    opts.default_locale = Some("fr".into());

    let router = test_router_with_error_response(
        opts,
        http::StatusCode::OK,
        json!({
            "code": "NEEDS_HEADER",
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
async fn existing_original_message_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = options_with_locale("fr", "NEEDS_HEADER", "Message traduit");
    opts.default_locale = Some("fr".into());

    let router = test_router_with_error_response(
        opts,
        http::StatusCode::BAD_REQUEST,
        json!({
            "code": "NEEDS_HEADER",
            "message": "Already translated",
            "originalMessage": "Original message"
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

    assert_eq!(body["message"], "Message traduit");
    assert_eq!(body["originalMessage"], "Original message");
    Ok(())
}

#[tokio::test]
async fn session_detection_reads_locale_from_session_cookie_hydration(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;

    use common::{session, signed_session_cookie};
    use openauth_core::api::{core_auth_async_endpoints, json_response, ApiErrorResponse};
    use openauth_core::context::create_auth_context_with_adapter;
    use openauth_core::db::DbAdapter;
    use openauth_core::db::DbFieldType;
    use openauth_core::options::{AdvancedOptions, UserAdditionalField, UserOptions};

    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user_with_locale(user(now), "fr").await;
    adapter
        .insert_session(session(now, now + time::Duration::hours(1)))
        .await;

    let opts = base_options()
        .default_locale("en")
        .detection([LocaleDetectionStrategy::Session]);

    let endpoint = create_auth_endpoint(
        "/session-cookie-error",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| {
            Box::pin(async move {
                json_response(
                    http::StatusCode::BAD_REQUEST,
                    &ApiErrorResponse {
                        code: "INVALID_EMAIL_OR_PASSWORD".to_owned(),
                        message: "Invalid email or password".to_owned(),
                        original_message: None,
                    },
                    Vec::new(),
                )
            })
        },
    );

    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            user: UserOptions {
                additional_fields: BTreeMap::from([(
                    "locale".to_owned(),
                    UserAdditionalField::new(DbFieldType::String),
                )]),
                ..UserOptions::default()
            },
            plugins: vec![i18n(opts)?],
            ..OpenAuthOptions::default()
        },
        Arc::clone(&adapter) as Arc<dyn DbAdapter>,
    )?;
    let mut endpoints = core_auth_async_endpoints(Arc::clone(&adapter) as Arc<dyn DbAdapter>);
    endpoints.push(endpoint);
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), endpoints)?;

    let cookie = signed_session_cookie("token_1")?;
    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/session-cookie-error",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["message"], "Email ou mot de passe invalide");
    assert_eq!(body["originalMessage"], "Invalid email or password");
    Ok(())
}

#[tokio::test]
async fn translates_invalid_origin_on_security_short_circuit(
) -> Result<(), Box<dyn std::error::Error>> {
    use openauth_core::api::core_auth_async_endpoints;
    use openauth_core::options::{AdvancedOptions, TrustedOriginOptions};

    let mut translations = IndexMap::new();
    translations.insert(
        "en".into(),
        translation_dictionary([("INVALID_ORIGIN", "Origine invalide")]),
    );
    let opts = I18nOptions::from_translations(translations).default_locale("en");

    let adapter = Arc::new(RouteAdapter::default());
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        advanced: AdvancedOptions::default(),
        plugins: vec![i18n(opts)?],
        ..OpenAuthOptions::default()
    })?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))?;

    let response = router
        .handle_async(json_request_with_headers(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"x"}"#,
            &[
                ("origin", "https://evil.example.com"),
                ("cookie", "session=abc"),
            ],
            None,
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_ORIGIN");
    assert_eq!(body["message"], "Origine invalide");
    Ok(())
}

#[tokio::test]
async fn translates_error_from_on_request_plugin_short_circuit(
) -> Result<(), Box<dyn std::error::Error>> {
    use openauth_core::api::json_response;
    use openauth_core::plugin::{AuthPlugin, PluginRequestAction};

    let mut translations = IndexMap::new();
    translations.insert(
        "en".into(),
        translation_dictionary([("EARLY_PLUGIN_ERROR", "Erreur anticipée")]),
    );
    let i18n_plugin = i18n(I18nOptions::from_translations(translations).default_locale("en"))?;
    let early_plugin = AuthPlugin::new("early-error").with_on_request(|_context, _request| {
        let response = json_response(
            http::StatusCode::BAD_REQUEST,
            &openauth_core::api::ApiErrorResponse {
                code: "EARLY_PLUGIN_ERROR".to_owned(),
                message: "Early plugin error".to_owned(),
                original_message: None,
            },
            Vec::new(),
        )?;
        Ok(PluginRequestAction::Respond(response))
    });

    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            plugins: vec![early_plugin, i18n_plugin],
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"x"}"#,
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Erreur anticipée");
    assert_eq!(body["originalMessage"], "Early plugin error");
    Ok(())
}
