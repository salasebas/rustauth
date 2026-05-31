#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "OAuth helper tests intentionally fail fast with contextual setup errors"
)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use josekit::jwk::Jwk;
use josekit::jwk::{Ed25519, P_256};
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256;
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
use josekit::jws::alg::hmac::HmacJwsAlgorithm::Hs256;
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_oauth::oauth2::{
    clear_jwks_cache, client_credentials_token, create_authorization_code_request,
    create_authorization_url, create_client_credentials_token_request,
    create_refresh_access_token_request, generate_code_challenge, get_oauth2_tokens,
    get_primary_client_id, refresh_access_token, validate_token, verify_access_token,
    verify_access_token_with_client, verify_jws_access_token,
    verify_jws_access_token_with_cache_config, AuthorizationCodeRequest, AuthorizationEndpoint,
    AuthorizationUrlRequest, ClientAuthentication, ClientCredentialsGrant,
    ClientCredentialsTokenRequest, ClientId, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo,
    OAuthError, OAuthHttpClient, OAuthHttpClientConfig, OAuthJwksCacheConfig, ProviderOptions,
    RedirectUri, RefreshAccessTokenRequest, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
    TokenEndpoint, TokenValidationOptions, VerifyAccessTokenOptions, VerifyAccessTokenRemote,
};
use serde_json::json;
use std::time::Duration;
use time::OffsetDateTime;

#[test]
fn create_authorization_url_includes_upstream_oauth_parameters() {
    let url = create_authorization_url(AuthorizationUrlRequest {
        id: "google".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Multiple(vec![
                "primary-client".to_owned(),
                "secondary-client".to_owned(),
            ])),
            redirect_uri: Some("https://override.example.com/callback".to_owned()),
            authorization_endpoint: Some("https://accounts.example.com/auth".to_owned()),
            ..ProviderOptions::default()
        },
        authorization_endpoint: "https://fallback.example.com/auth".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        state: "state-123".to_owned(),
        code_verifier: Some("verifier-123".to_owned()),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        claims: vec!["profile".to_owned()],
        prompt: Some("consent".to_owned()),
        access_type: Some("offline".to_owned()),
        login_hint: Some("ada@example.com".to_owned()),
        additional_params: BTreeMap::from([("resource".to_owned(), "calendar".to_owned())]),
        ..AuthorizationUrlRequest::default()
    })
    .expect("authorization url should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://accounts.example.com/auth")
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "response_type")
            .map(|(_, value)| value.into_owned()),
        Some("code".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "client_id")
            .map(|(_, value)| value.into_owned()),
        Some("primary-client".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.into_owned()),
        Some("openid email".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .map(|(_, value)| value.into_owned()),
        Some("https://override.example.com/callback".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "code_challenge_method")
            .map(|(_, value)| value.into_owned()),
        Some("S256".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "prompt")
            .map(|(_, value)| value.into_owned()),
        Some("consent".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "resource")
            .map(|(_, value)| value.into_owned()),
        Some("calendar".to_owned())
    );
    assert!(url
        .query_pairs()
        .any(|(key, value)| key == "claims" && value.contains("email_verified")));
}

#[test]
fn create_authorization_url_additional_params_overwrite_existing_params() {
    let url = create_authorization_url(AuthorizationUrlRequest {
        id: "generic".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            ..ProviderOptions::default()
        },
        authorization_endpoint: "https://auth.example.com/authorize".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        state: "state".to_owned(),
        scopes: vec!["openid".to_owned()],
        prompt: Some("select_account".to_owned()),
        additional_params: BTreeMap::from([
            ("scope".to_owned(), "profile email".to_owned()),
            ("prompt".to_owned(), "consent".to_owned()),
        ]),
        ..AuthorizationUrlRequest::default()
    })
    .expect("authorization url should build");

    let scopes = url
        .query_pairs()
        .filter(|(key, _)| key == "scope")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    let prompts = url
        .query_pairs()
        .filter(|(key, _)| key == "prompt")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();

    assert_eq!(scopes, vec!["profile email"]);
    assert_eq!(prompts, vec!["consent"]);
}

#[test]
fn create_authorization_url_standard_params_overwrite_endpoint_query_params() {
    let url = create_authorization_url(AuthorizationUrlRequest {
        id: "generic".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            ..ProviderOptions::default()
        },
        authorization_endpoint: concat!(
            "https://auth.example.com/authorize?",
            "client_id=stale-client&",
            "scope=stale-scope&",
            "redirect_uri=https%3A%2F%2Fstale.example.com%2Fcallback&",
            "code_challenge_method=plain&",
            "code_challenge=stale-challenge&",
            "tenant=kept"
        )
        .to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        state: "state".to_owned(),
        code_verifier: Some("verifier".to_owned()),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        ..AuthorizationUrlRequest::default()
    })
    .expect("authorization url should build");

    let values = |key: &str| {
        url.query_pairs()
            .filter(|(param, _)| param == key)
            .map(|(_, value)| value.into_owned())
            .collect::<Vec<_>>()
    };

    assert_eq!(values("client_id"), vec!["client-id"]);
    assert_eq!(values("scope"), vec!["openid email"]);
    assert_eq!(
        values("redirect_uri"),
        vec!["https://app.example.com/callback"]
    );
    assert_eq!(values("code_challenge_method"), vec!["S256"]);
    assert_eq!(
        values("code_challenge"),
        vec!["iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ"]
    );
    assert_eq!(values("tenant"), vec!["kept"]);
}

#[test]
fn request_builders_support_post_and_basic_authentication() {
    let post = create_authorization_code_request(AuthorizationCodeRequest {
        code: "code-123".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            client_secret: Some("client-secret".to_owned()),
            ..ProviderOptions::default()
        },
        code_verifier: Some("verifier".to_owned()),
        authentication: ClientAuthentication::Post,
        resource: vec!["resource-a".to_owned(), "resource-b".to_owned()],
        additional_params: BTreeMap::from([("audience".to_owned(), "api".to_owned())]),
        ..AuthorizationCodeRequest::default()
    })
    .expect("post auth request should build");

    assert_eq!(
        post.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(post.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(post.form_value("client_id"), Some("client-id"));
    assert_eq!(post.form_value("client_secret"), Some("client-secret"));
    assert_eq!(
        post.form_values("resource"),
        vec!["resource-a", "resource-b"]
    );

    let basic = create_refresh_access_token_request(RefreshAccessTokenRequest {
        refresh_token: "refresh-token".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            client_secret: Some("client-secret".to_owned()),
            ..ProviderOptions::default()
        },
        authentication: ClientAuthentication::Basic,
        ..RefreshAccessTokenRequest::default()
    })
    .expect("basic auth request should build");

    assert_eq!(basic.form_value("client_id"), None);
    assert_eq!(
        basic.header("authorization"),
        Some("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=")
    );

    let client_credentials =
        create_client_credentials_token_request(ClientCredentialsTokenRequest {
            options: ProviderOptions {
                client_id: Some(ClientId::Single("client-id".to_owned())),
                client_secret: Some("client-secret".to_owned()),
                ..ProviderOptions::default()
            },
            scope: Some("admin".to_owned()),
            authentication: ClientAuthentication::Basic,
            resource: vec!["resource-a".to_owned()],
        })
        .expect("client credentials request should build");

    assert_eq!(
        client_credentials.form_value("grant_type"),
        Some("client_credentials")
    );
    assert_eq!(client_credentials.form_value("scope"), Some("admin"));
    assert_eq!(
        client_credentials.header("authorization"),
        Some("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=")
    );
}

#[test]
fn basic_authentication_form_encodes_reserved_and_non_ascii_credentials() {
    use base64::Engine as _;

    let decode_basic = |request: &openauth_oauth::oauth2::OAuthFormRequest| {
        let encoded = request
            .header("authorization")
            .and_then(|header| header.strip_prefix("Basic "))
            .expect("basic authorization header should be set")
            .to_owned();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("credentials should be valid base64"),
        )
        .expect("decoded credentials should be utf-8")
    };

    let reserved = create_refresh_access_token_request(RefreshAccessTokenRequest {
        refresh_token: "refresh-token".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("a:b c".to_owned())),
            client_secret: Some("é+&=%".to_owned()),
            ..ProviderOptions::default()
        },
        authentication: ClientAuthentication::Basic,
        ..RefreshAccessTokenRequest::default()
    })
    .expect("basic auth request should build");

    // Each component is form-encoded independently (RFC 6749 §2.3.1), so reserved and
    // non-ASCII bytes survive Base64 and the only literal `:` is the separator a server
    // splits on before decoding each half.
    let decoded = decode_basic(&reserved);
    assert_eq!(decoded, "a%3Ab+c:%C3%A9%2B%26%3D%25");
    let (id, secret) = decoded
        .split_once(':')
        .expect("exactly one separator colon should remain");
    assert_eq!(form_urldecode(id), "a:b c");
    assert_eq!(form_urldecode(secret), "é+&=%");

    // Compatibility: simple unreserved ASCII credentials are unchanged on the wire.
    let simple = create_refresh_access_token_request(RefreshAccessTokenRequest {
        refresh_token: "refresh-token".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            client_secret: Some("client-secret".to_owned()),
            ..ProviderOptions::default()
        },
        authentication: ClientAuthentication::Basic,
        ..RefreshAccessTokenRequest::default()
    })
    .expect("basic auth request should build");
    assert_eq!(decode_basic(&simple), "client-id:client-secret");
}

#[test]
fn authorization_code_additional_params_do_not_overwrite_standard_fields() {
    let request = create_authorization_code_request(AuthorizationCodeRequest {
        code: "code-123".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            client_secret: Some("client-secret".to_owned()),
            ..ProviderOptions::default()
        },
        additional_params: BTreeMap::from([
            ("code".to_owned(), "attacker-code".to_owned()),
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("audience".to_owned(), "api".to_owned()),
        ]),
        ..AuthorizationCodeRequest::default()
    })
    .expect("authorization code request should build");

    assert_eq!(request.form_value("code"), Some("code-123"));
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("audience"), Some("api"));
}

#[test]
fn client_credentials_requires_client_id_and_secret() {
    let missing_client_id =
        create_client_credentials_token_request(ClientCredentialsTokenRequest {
            options: ProviderOptions {
                client_secret: Some("client-secret".to_owned()),
                ..ProviderOptions::default()
            },
            ..ClientCredentialsTokenRequest::default()
        })
        .expect_err("client credentials should require a client_id");

    assert_eq!(
        missing_client_id.to_string(),
        "missing OAuth provider option `client_id`"
    );

    let missing_client_secret =
        create_client_credentials_token_request(ClientCredentialsTokenRequest {
            options: ProviderOptions {
                client_id: Some(ClientId::Single("client-id".to_owned())),
                ..ProviderOptions::default()
            },
            ..ClientCredentialsTokenRequest::default()
        })
        .expect_err("client credentials should require a client_secret");

    assert_eq!(
        missing_client_secret.to_string(),
        "missing OAuth provider option `client_secret`"
    );
}

#[test]
fn direct_request_builders_reject_invalid_required_fields() {
    let authorization_url = create_authorization_url(AuthorizationUrlRequest {
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            ..ProviderOptions::default()
        },
        authorization_endpoint: "notaurl".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        state: String::new(),
        ..AuthorizationUrlRequest::default()
    })
    .expect_err("authorization URL should validate direct struct construction");
    assert!(authorization_url
        .to_string()
        .contains("authorization state"));

    let authorization_code = create_authorization_code_request(AuthorizationCodeRequest {
        redirect_uri: "https://app.example.com/callback".to_owned(),
        options: provider_options(),
        ..AuthorizationCodeRequest::default()
    })
    .expect_err("authorization code should be required");
    assert!(authorization_code
        .to_string()
        .contains("authorization code"));

    let refresh = create_refresh_access_token_request(RefreshAccessTokenRequest {
        options: provider_options(),
        ..RefreshAccessTokenRequest::default()
    })
    .expect_err("refresh token should be required");
    assert!(refresh.to_string().contains("refresh_token"));

    let invalid_redirect = create_authorization_code_request(AuthorizationCodeRequest {
        code: "code".to_owned(),
        redirect_uri: "notaurl".to_owned(),
        options: provider_options(),
        ..AuthorizationCodeRequest::default()
    })
    .expect_err("redirect URI should be validated");
    assert!(invalid_redirect.to_string().contains("OAuth URL"));
}

#[test]
fn client_authentication_matrix_handles_public_and_confidential_clients() {
    let public_refresh = create_refresh_access_token_request(RefreshAccessTokenRequest {
        refresh_token: "refresh-token".to_owned(),
        options: ProviderOptions {
            client_id: Some(ClientId::Single("public-client".to_owned())),
            ..ProviderOptions::default()
        },
        authentication: ClientAuthentication::Post,
        ..RefreshAccessTokenRequest::default()
    })
    .expect("public refresh token request can omit client secret");
    assert_eq!(
        public_refresh.form_value("client_id"),
        Some("public-client")
    );
    assert_eq!(public_refresh.form_value("client_secret"), None);

    let missing_basic_client = create_refresh_access_token_request(RefreshAccessTokenRequest {
        refresh_token: "refresh-token".to_owned(),
        options: ProviderOptions {
            client_secret: Some("secret".to_owned()),
            ..ProviderOptions::default()
        },
        authentication: ClientAuthentication::Basic,
        ..RefreshAccessTokenRequest::default()
    })
    .expect_err("basic authentication should require a client_id");
    assert!(missing_basic_client.to_string().contains("client_id"));

    let empty_secret = create_client_credentials_token_request(ClientCredentialsTokenRequest {
        options: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            client_secret: Some(String::new()),
            ..ProviderOptions::default()
        },
        ..ClientCredentialsTokenRequest::default()
    })
    .expect_err("client credentials should reject empty secret");
    assert!(empty_secret.to_string().contains("client_secret"));
}

#[test]
fn validated_constructors_reject_invalid_required_values() {
    assert!(AuthorizationEndpoint::new("https://provider.example.com/authorize").is_ok());
    assert!(TokenEndpoint::new("https://provider.example.com/token").is_ok());
    assert!(RedirectUri::new("https://app.example.com/callback").is_ok());

    assert!(AuthorizationUrlRequest::try_new(
        "provider",
        ProviderOptions::default(),
        "https://provider.example.com/authorize",
        "https://app.example.com/callback",
        "state"
    )
    .is_err());
    assert!(AuthorizationCodeRequest::try_new(
        "",
        "https://app.example.com/callback",
        ProviderOptions::default()
    )
    .is_err());
    assert!(RefreshAccessTokenRequest::try_new("", ProviderOptions::default()).is_err());
    assert!(VerifyAccessTokenOptions::remote(VerifyAccessTokenRemote {
        introspect_url: "https://provider.example.com/introspect".to_owned(),
        client_id: String::new(),
        client_secret: "secret".to_owned(),
        force: true,
    })
    .is_err());
}

#[test]
fn oauth_http_client_config_validates_timeout() {
    let error = OAuthHttpClient::from_config(OAuthHttpClientConfig {
        timeout: Duration::ZERO,
        ..OAuthHttpClientConfig::default()
    })
    .expect_err("zero timeout should be invalid");

    assert!(error
        .to_string()
        .contains("timeout must be greater than zero"));
}

#[test]
fn token_helpers_reject_malformed_token_responses() {
    for malformed in [
        json!({}),
        json!({ "access_token": 42 }),
        json!({ "access_token": "access", "scope": ["openid", 42] }),
        json!({ "access_token": "access", "expires_in": -1 }),
        json!({ "access_token": "access", "expires_in": i64::MAX }),
        json!("not-an-object"),
    ] {
        assert!(
            get_oauth2_tokens(malformed).is_err(),
            "malformed token response should be rejected"
        );
    }
}

#[test]
fn token_helpers_parse_raw_scopes_expiry_and_pkce() {
    let tokens = get_oauth2_tokens(json!({
        "token_type": "Bearer",
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 3600,
        "refresh_token_expires_in": 7200,
        "scope": ["openid", "email"],
        "id_token": "id-token",
        "provider_specific": true
    }))
    .expect("tokens should parse");

    assert_eq!(tokens.token_type.as_deref(), Some("Bearer"));
    assert_eq!(tokens.access_token.as_deref(), Some("access"));
    assert_eq!(tokens.scopes, vec!["openid", "email"]);
    assert_eq!(tokens.raw["provider_specific"], true);
    assert!(tokens.access_token_expires_at.is_some());
    assert!(tokens.refresh_token_expires_at.is_some());
    assert_eq!(
        get_primary_client_id(&Some(ClientId::Multiple(vec![
            "first".to_owned(),
            "second".to_owned()
        ]))),
        Some("first")
    );
    assert_eq!(
        generate_code_challenge("verifier").expect("challenge should build"),
        "iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ"
    );
}

#[tokio::test]
async fn network_token_helpers_redact_structured_and_plaintext_sensitive_errors() {
    let json_server = JsonServer::spawn_status(
        400,
        json!({
            "error": "invalid_grant",
            "error_description": "authorization code rejected",
            "code": "secret-code",
            "token": "secret-token",
            "client_assertion": "secret-assertion",
            "subject_token": "secret-subject-token",
            "device_code": "secret-device-code"
        }),
    );
    let json_error = refresh_access_token(ClientTokenRequest {
        token_endpoint: json_server.url(),
        request: RefreshAccessTokenRequest {
            refresh_token: "secret-refresh-token".to_owned(),
            options: provider_options(),
            ..RefreshAccessTokenRequest::default()
        },
    })
    .await
    .expect_err("structured OAuth error should be redacted")
    .to_string();
    assert!(json_error.contains("invalid_grant"));
    assert!(!json_error.contains("secret-code"));
    assert!(!json_error.contains("secret-token"));
    assert!(!json_error.contains("secret-assertion"));
    assert!(!json_error.contains("secret-subject-token"));
    assert!(!json_error.contains("secret-device-code"));

    let text_server = RawServer::spawn_status(
        500,
        "text/plain",
        "device_code=secret-device-code&token=secret-token",
    );
    let text_error = refresh_access_token(ClientTokenRequest {
        token_endpoint: text_server.url(),
        request: RefreshAccessTokenRequest {
            refresh_token: "secret-refresh-token".to_owned(),
            options: provider_options(),
            ..RefreshAccessTokenRequest::default()
        },
    })
    .await
    .expect_err("plaintext OAuth error should be redacted")
    .to_string();
    assert!(!text_error.contains("secret-device-code"));
    assert!(!text_error.contains("secret-token"));
}

#[tokio::test]
async fn network_token_helpers_reject_invalid_success_json() {
    let server = RawServer::spawn_status(200, "application/json", "{not-json");
    let error = refresh_access_token(ClientTokenRequest {
        token_endpoint: server.url(),
        request: RefreshAccessTokenRequest {
            refresh_token: "refresh-token".to_owned(),
            options: provider_options(),
            ..RefreshAccessTokenRequest::default()
        },
    })
    .await
    .expect_err("invalid success JSON should be rejected");

    assert!(error.to_string().contains("invalid OAuth response"));
}

#[tokio::test]
async fn network_token_helpers_post_form_requests_and_parse_responses() {
    let refresh_server = JsonServer::spawn(json!({
        "access_token": "new-access",
        "refresh_token": "new-refresh",
        "expires_in": 60,
        "refresh_token_expires_in": 120,
        "token_type": "Bearer",
        "scope": "openid email"
    }));
    let refreshed = refresh_access_token(ClientTokenRequest {
        token_endpoint: refresh_server.url(),
        request: RefreshAccessTokenRequest {
            refresh_token: "old-refresh".to_owned(),
            options: provider_options(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        },
    })
    .await
    .expect("refresh token should parse response");

    assert_eq!(refreshed.access_token.as_deref(), Some("new-access"));
    assert_eq!(refreshed.refresh_token.as_deref(), Some("new-refresh"));
    assert_eq!(refreshed.scopes, vec!["openid", "email"]);
    assert!(refresh_server
        .request_body()
        .contains("grant_type=refresh_token"));

    let client_server = JsonServer::spawn(json!({
        "access_token": "client-access",
        "expires_in": 60,
        "token_type": "Bearer",
        "scope": "admin"
    }));
    let client_tokens = client_credentials_token(ClientCredentialsGrant {
        token_endpoint: client_server.url(),
        request: ClientCredentialsTokenRequest {
            options: ProviderOptions {
                client_id: Some(ClientId::Single("client-id".to_owned())),
                client_secret: Some("client-secret".to_owned()),
                ..ProviderOptions::default()
            },
            scope: Some("admin".to_owned()),
            authentication: ClientAuthentication::Post,
            resource: Vec::new(),
        },
    })
    .await
    .expect("client credentials should parse response");

    assert_eq!(client_tokens.access_token.as_deref(), Some("client-access"));
    assert_eq!(client_tokens.scopes, vec!["admin"]);
}

#[tokio::test]
async fn network_token_helpers_parse_oauth_error_without_leaking_secrets() {
    let server = JsonServer::spawn_status(
        400,
        json!({
            "error": "invalid_client",
            "error_description": "client_secret rejected",
            "access_token": "secret-access-token"
        }),
    );

    let error = client_credentials_token(ClientCredentialsGrant {
        token_endpoint: server.url(),
        request: ClientCredentialsTokenRequest {
            options: ProviderOptions {
                client_id: Some(ClientId::Single("client-id".to_owned())),
                client_secret: Some("client-secret".to_owned()),
                ..ProviderOptions::default()
            },
            authentication: ClientAuthentication::Post,
            ..ClientCredentialsTokenRequest::default()
        },
    })
    .await
    .expect_err("OAuth error body should become a typed error");

    assert!(error.to_string().contains("invalid_client"));
    assert!(!error.to_string().contains("secret-access-token"));
}

#[tokio::test]
async fn network_token_helpers_redact_sensitive_oauth_error_descriptions() {
    let server = JsonServer::spawn_status(
        400,
        json!({
            "error": "invalid_grant",
            "error_description": "refresh_token=secret-refresh-token was rejected"
        }),
    );

    let error = refresh_access_token(ClientTokenRequest {
        token_endpoint: server.url(),
        request: RefreshAccessTokenRequest {
            refresh_token: "secret-refresh-token".to_owned(),
            options: provider_options(),
            ..RefreshAccessTokenRequest::default()
        },
    })
    .await
    .expect_err("OAuth error description should be redacted");

    assert!(error.to_string().contains("invalid_grant"));
    assert!(!error.to_string().contains("secret-refresh-token"));
}

#[tokio::test]
async fn verify_jws_access_token_cache_config_expires_and_limits_entries() {
    clear_jwks_cache().expect("cache should clear");
    let (token_a, jwk_a) = signed_hs256_token("ttl-key-a", json!({ "sub": "user-a" }));
    let server_a = JsonServer::spawn_many(vec![
        JsonResponse::ok(json!({ "keys": [jwk_a.clone()] })),
        JsonResponse::ok(json!({ "keys": [jwk_a] })),
    ]);
    verify_jws_access_token_with_cache_config(
        &token_a,
        &server_a.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
        OAuthJwksCacheConfig {
            ttl: Duration::from_millis(1),
            max_entries: 8,
        },
    )
    .await
    .expect("first verification should fetch jwks");
    thread::sleep(Duration::from_millis(5));
    verify_jws_access_token_with_cache_config(
        &token_a,
        &server_a.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
        OAuthJwksCacheConfig {
            ttl: Duration::from_millis(1),
            max_entries: 8,
        },
    )
    .await
    .expect("expired cache entry should refetch");
    assert_eq!(server_a.request_count(), 2);

    clear_jwks_cache().expect("cache should clear");
    let (token_b, jwk_b) = signed_hs256_token("limit-key-b", json!({ "sub": "user-b" }));
    let (token_c, jwk_c) = signed_hs256_token("limit-key-c", json!({ "sub": "user-c" }));
    let server_b = JsonServer::spawn_many(vec![
        JsonResponse::ok(json!({ "keys": [jwk_b.clone()] })),
        JsonResponse::ok(json!({ "keys": [jwk_b] })),
    ]);
    let server_c = JsonServer::spawn(json!({ "keys": [jwk_c] }));
    let cache_config = OAuthJwksCacheConfig {
        ttl: Duration::from_secs(60),
        max_entries: 1,
    };
    verify_jws_access_token_with_cache_config(
        &token_b,
        &server_b.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
        cache_config,
    )
    .await
    .expect("first URL should fetch");
    verify_jws_access_token_with_cache_config(
        &token_c,
        &server_c.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
        cache_config,
    )
    .await
    .expect("second URL should fetch and evict first URL");
    verify_jws_access_token_with_cache_config(
        &token_b,
        &server_b.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
        cache_config,
    )
    .await
    .expect("evicted first URL should refetch");
    assert_eq!(server_b.request_count(), 2);
}

#[tokio::test]
async fn verify_access_token_remote_fallback_only_for_opaque_or_malformed_jws() {
    let remote = JsonServer::spawn_many(vec![
        JsonResponse::ok(json!({
            "active": true,
            "sub": "opaque-with-dots",
            "aud": "api-client",
            "iss": "https://issuer.example.com",
            "scope": "read"
        })),
        JsonResponse::ok(json!({
            "active": true,
            "sub": "malformed-jws",
            "aud": "api-client",
            "iss": "https://issuer.example.com",
            "scope": "read"
        })),
    ]);
    let options = remote_verify_options(remote.url(), vec!["read".to_owned()]);
    let opaque = verify_access_token("opaque.token.value", options.clone())
        .await
        .expect("opaque token with dots should fall back to remote introspection");
    assert_eq!(opaque["sub"], "opaque-with-dots");
    let malformed = verify_access_token("not-a-valid-jws.but.three-parts", options)
        .await
        .expect("malformed JWS should fall back to remote introspection");
    assert_eq!(malformed["sub"], "malformed-jws");

    let (expired_token, expired_jwk) = signed_hs256_token(
        "expired-no-fallback",
        json!({
            "sub": "user-123",
            "exp": OffsetDateTime::now_utc().unix_timestamp() - 120
        }),
    );
    let local = JsonServer::spawn(json!({ "keys": [expired_jwk] }));
    let remote = JsonServer::spawn_many(Vec::new());
    let error = verify_access_token(
        &expired_token,
        VerifyAccessTokenOptions {
            jwks_url: Some(local.url()),
            remote_verify: Some(VerifyAccessTokenRemote {
                introspect_url: remote.url(),
                client_id: "client-id".to_owned(),
                client_secret: "client-secret".to_owned(),
                force: false,
            }),
            verify_options: TokenValidationOptions::default().allow_hmac_algorithms(),
            scopes: vec!["read".to_owned()],
        },
    )
    .await
    .expect_err("expired JWS should not fall back to remote introspection");
    assert!(error.to_string().contains("token expired"));
    assert_eq!(remote.request_count(), 0);
}

#[tokio::test]
async fn verify_access_token_rejects_remote_missing_active_and_missing_audience() {
    let missing_active = JsonServer::spawn(json!({
        "sub": "user-123",
        "scope": "read"
    }));
    let error = verify_access_token(
        "opaque-token",
        remote_verify_options(missing_active.url(), vec!["read".to_owned()]),
    )
    .await
    .expect_err("remote introspection should require active");
    assert!(error.to_string().contains("active"));

    let missing_audience = JsonServer::spawn(json!({
        "active": true,
        "sub": "user-123",
        "scope": "read"
    }));
    let error = verify_access_token(
        "opaque-token",
        VerifyAccessTokenOptions {
            remote_verify: Some(VerifyAccessTokenRemote {
                introspect_url: missing_audience.url(),
                client_id: "client-id".to_owned(),
                client_secret: "client-secret".to_owned(),
                force: true,
            }),
            verify_options: TokenValidationOptions {
                audience: vec!["api".to_owned()],
                ..TokenValidationOptions::default()
            },
            scopes: vec!["read".to_owned()],
            jwks_url: None,
        },
    )
    .await
    .expect_err("configured audience should require aud in introspection payload");
    assert!(error.to_string().contains("audience"));
}

#[tokio::test]
async fn validate_token_verifies_jwks_audience_issuer_and_scope() {
    let (token, jwk) = signed_hs256_token(
        "test-key",
        json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "client-id",
            "scope": "read write"
        }),
    );
    let public_jwks = json!({ "keys": [jwk] });
    let server = JsonServer::spawn(public_jwks);

    let verified = validate_token(
        &token,
        &server.url(),
        TokenValidationOptions {
            audience: vec!["client-id".to_owned()],
            issuer: vec!["https://issuer.example.com".to_owned()],
            ..TokenValidationOptions::default()
        }
        .allow_hmac_algorithms(),
    )
    .await
    .expect("token should verify");

    assert_eq!(verified.payload["sub"], "user-123");
    assert!(validate_token(
        &token,
        &server.url(),
        TokenValidationOptions {
            audience: vec!["wrong-client".to_owned()],
            issuer: vec!["https://issuer.example.com".to_owned()],
            ..TokenValidationOptions::default()
        }
        .allow_hmac_algorithms(),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn validate_token_rejects_hmac_algorithms_by_default() {
    let (token, jwk) = signed_hs256_token(
        "hmac-key",
        json!({
            "sub": "user-123"
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk] }));

    let error = validate_token(&token, &server.url(), TokenValidationOptions::default())
        .await
        .expect_err("default validation should reject HMAC algorithms");

    assert_eq!(error.to_string(), "unsupported OAuth JWT algorithm `HS256`");
}

#[tokio::test]
async fn validate_token_accepts_hmac_algorithms_when_explicitly_allowed() {
    let (token, jwk) = signed_hs256_token(
        "hmac-key-explicit",
        json!({
            "sub": "user-123"
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk] }));

    let result = validate_token(
        &token,
        &server.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
    )
    .await
    .expect("explicit HMAC opt-in should verify");

    assert_eq!(result.payload["sub"], "user-123");
}

#[tokio::test]
async fn validate_token_rejects_expired_tokens() {
    let (token, jwk) = signed_hs256_token(
        "expired-key",
        json!({
            "sub": "user-123",
            "iss": "https://issuer.example.com",
            "aud": "client-id",
            "exp": OffsetDateTime::now_utc().unix_timestamp() - 60
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk] }));

    assert!(validate_token(
        &token,
        &server.url(),
        TokenValidationOptions {
            audience: vec!["client-id".to_owned()],
            issuer: vec!["https://issuer.example.com".to_owned()],
            ..TokenValidationOptions::default()
        },
    )
    .await
    .is_err());
}

#[tokio::test]
async fn validate_token_verifies_rs256_es256_and_eddsa_tokens() {
    let cases = [
        signed_asymmetric_token("RS256", "rsa-key"),
        signed_asymmetric_token("ES256", "ec-key"),
        signed_asymmetric_token("EdDSA", "ed-key"),
    ];

    for (token, jwk) in cases {
        let server = JsonServer::spawn(json!({ "keys": [jwk] }));
        let result = validate_token(&token, &server.url(), TokenValidationOptions::default())
            .await
            .expect("token should verify");

        assert_eq!(result.payload["sub"], "user-123");
    }
}

#[tokio::test]
async fn verify_access_token_rejects_required_claims_with_wrong_types() {
    let server = JsonServer::spawn(json!({
            "active": true,
            "sub": 123,
            "iss": "https://issuer.example.com",
            "aud": "client-id",
            "scope": "read",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 300
    }));

    let error = verify_access_token(
        "opaque-token",
        VerifyAccessTokenOptions {
            verify_options: TokenValidationOptions {
                audience: vec!["client-id".to_owned()],
                issuer: vec!["https://issuer.example.com".to_owned()],
                ..TokenValidationOptions::default()
            }
            .require_standard_claims(),
            scopes: vec!["read".to_owned()],
            jwks_url: None,
            remote_verify: Some(VerifyAccessTokenRemote {
                introspect_url: server.url(),
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
                force: true,
            }),
        },
    )
    .await
    .expect_err("required sub claim must be a string");

    assert!(error.to_string().contains("invalid OAuth claim `sub`"));
}

#[tokio::test]
async fn verify_jws_access_token_reuses_cached_jwks_for_known_kid() {
    clear_jwks_cache().expect("cache should clear");
    let (token, jwk) = signed_asymmetric_token("RS256", "cached-rsa-key");
    let server = JsonServer::spawn_many(vec![JsonResponse::ok(json!({ "keys": [jwk] }))]);

    verify_jws_access_token(&token, &server.url(), TokenValidationOptions::default())
        .await
        .expect("first verification should fetch jwks");
    verify_jws_access_token(&token, &server.url(), TokenValidationOptions::default())
        .await
        .expect("second verification should use cached jwks");

    assert_eq!(server.request_count(), 1);
}

#[tokio::test]
async fn verify_jws_access_token_refetches_jwks_for_unknown_kid() {
    clear_jwks_cache().expect("cache should clear");
    let (first_token, first_jwk) = signed_asymmetric_token("RS256", "first-rsa-key");
    let (second_token, second_jwk) = signed_asymmetric_token("RS256", "second-rsa-key");
    let server = JsonServer::spawn_many(vec![
        JsonResponse::ok(json!({ "keys": [first_jwk] })),
        JsonResponse::ok(json!({ "keys": [second_jwk] })),
    ]);

    verify_jws_access_token(
        &first_token,
        &server.url(),
        TokenValidationOptions::default(),
    )
    .await
    .expect("first verification should fetch first jwks");
    verify_jws_access_token(
        &second_token,
        &server.url(),
        TokenValidationOptions::default(),
    )
    .await
    .expect("unknown kid should refetch jwks");

    assert_eq!(server.request_count(), 2);
}

#[tokio::test]
async fn clear_jwks_cache_forces_next_jwks_fetch() {
    clear_jwks_cache().expect("cache should clear");
    let (token, jwk) = signed_asymmetric_token("RS256", "clear-cache-rsa-key");
    let server = JsonServer::spawn_many(vec![
        JsonResponse::ok(json!({ "keys": [jwk.clone()] })),
        JsonResponse::ok(json!({ "keys": [jwk] })),
    ]);

    verify_jws_access_token(&token, &server.url(), TokenValidationOptions::default())
        .await
        .expect("first verification should fetch jwks");
    clear_jwks_cache().expect("cache should clear");
    verify_jws_access_token(&token, &server.url(), TokenValidationOptions::default())
        .await
        .expect("cache clear should force refetch");

    assert_eq!(server.request_count(), 2);
}

#[tokio::test]
async fn validate_token_rejects_missing_kid_empty_jwks_and_wrong_key() {
    let (missing_kid, jwk_without_kid) = signed_hs256_token(
        "",
        json!({
            "sub": "user-123"
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk_without_kid] }));
    assert!(validate_token(
        &missing_kid,
        &server.url(),
        TokenValidationOptions::default().allow_hmac_algorithms()
    )
    .await
    .is_err());

    let (wrong_key_token, mut wrong_jwk) = signed_hs256_token(
        "original-kid",
        json!({
            "sub": "user-123"
        }),
    );
    wrong_jwk.set_key_id("different-kid");
    let server = JsonServer::spawn(json!({ "keys": [wrong_jwk] }));
    assert!(validate_token(
        &wrong_key_token,
        &server.url(),
        TokenValidationOptions::default().allow_hmac_algorithms()
    )
    .await
    .is_err());

    let (empty_jwks_token, _) = signed_hs256_token(
        "missing-in-jwks",
        json!({
            "sub": "user-123"
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [] }));
    assert!(validate_token(
        &empty_jwks_token,
        &server.url(),
        TokenValidationOptions::default().allow_hmac_algorithms()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn verify_access_token_validates_remote_audience_issuer_and_scopes() {
    let server = JsonServer::spawn(json!({
        "active": true,
        "sub": "user-123",
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read write"
    }));

    let payload = verify_access_token(
        "opaque-token",
        VerifyAccessTokenOptions {
            verify_options: TokenValidationOptions {
                audience: vec!["api-client".to_owned()],
                issuer: vec!["https://issuer.example.com".to_owned()],
                ..TokenValidationOptions::default()
            },
            scopes: vec!["read".to_owned()],
            jwks_url: None,
            remote_verify: Some(VerifyAccessTokenRemote {
                introspect_url: server.url(),
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
                force: true,
            }),
        },
    )
    .await
    .expect("remote introspection should pass");

    assert_eq!(payload["sub"], "user-123");
    assert!(server
        .request_body()
        .contains("token_type_hint=access_token"));
}

#[tokio::test]
async fn verify_access_token_rejects_remote_audience_issuer_scope_and_inactive_tokens() {
    let wrong_audience = JsonServer::spawn(json!({
        "active": true,
        "aud": "wrong-client",
        "iss": "https://issuer.example.com",
        "scope": "read"
    }));
    assert!(verify_access_token(
        "opaque-token",
        remote_verify_options(wrong_audience.url(), vec!["read".to_owned()]),
    )
    .await
    .is_err());

    let missing_scope = JsonServer::spawn(json!({
        "active": true,
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read"
    }));
    assert!(verify_access_token(
        "opaque-token",
        remote_verify_options(missing_scope.url(), vec!["write".to_owned()]),
    )
    .await
    .is_err());

    let inactive = JsonServer::spawn(json!({
        "active": false,
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read"
    }));
    assert!(verify_access_token(
        "opaque-token",
        remote_verify_options(inactive.url(), vec!["read".to_owned()]),
    )
    .await
    .is_err());

    let missing_active = JsonServer::spawn(json!({
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read"
    }));
    let error = verify_access_token(
        "opaque-token",
        remote_verify_options(missing_active.url(), vec!["read".to_owned()]),
    )
    .await
    .expect_err("introspection without active must be invalid");

    assert!(error
        .to_string()
        .contains("missing OAuth token field `active`"));
}

#[tokio::test]
async fn verify_access_token_falls_back_to_remote_for_opaque_tokens() {
    let remote = JsonServer::spawn(json!({
        "active": true,
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read"
    }));
    let remote_verify = VerifyAccessTokenRemote {
        introspect_url: remote.url(),
        client_id: "client".to_owned(),
        client_secret: "secret".to_owned(),
        force: false,
    };

    let payload = verify_access_token(
        "opaque-token",
        VerifyAccessTokenOptions {
            verify_options: TokenValidationOptions {
                audience: vec!["api-client".to_owned()],
                issuer: vec!["https://issuer.example.com".to_owned()],
                ..TokenValidationOptions::default()
            },
            scopes: vec!["read".to_owned()],
            jwks_url: Some("http://127.0.0.1:1/jwks".to_owned()),
            remote_verify: Some(remote_verify),
        },
    )
    .await
    .expect("opaque token should fall back to remote introspection");

    assert_eq!(payload["active"], true);
}

#[tokio::test]
async fn verify_access_token_accepts_injected_http_client_for_introspection() {
    let remote = JsonServer::spawn(json!({
        "active": true,
        "aud": "api-client",
        "iss": "https://issuer.example.com",
        "scope": "read"
    }));
    let client = OAuthHttpClient::default_client().expect("client should build");

    let payload = verify_access_token_with_client(
        "opaque-token",
        remote_verify_options(remote.url(), vec!["read".to_owned()]),
        &client,
    )
    .await
    .expect("injected client should verify token");

    assert_eq!(payload["active"], true);
}

#[tokio::test]
async fn verify_jws_access_token_maps_azp_to_client_id() {
    let (token, jwk) = signed_hs256_token(
        "azp-key",
        json!({
            "sub": "user-123",
            "azp": "authorized-party"
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk] }));

    let payload = verify_jws_access_token(
        &token,
        &server.url(),
        TokenValidationOptions::default().allow_hmac_algorithms(),
    )
    .await
    .expect("jws access token should verify")
    .payload;

    assert_eq!(payload["client_id"], "authorized-party");
}

fn form_urldecode(value: &str) -> String {
    url::form_urlencoded::parse(format!("x={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_default()
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::Single("client-id".to_owned())),
        client_secret: Some("client-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn remote_verify_options(introspect_url: String, scopes: Vec<String>) -> VerifyAccessTokenOptions {
    VerifyAccessTokenOptions {
        verify_options: TokenValidationOptions {
            audience: vec!["api-client".to_owned()],
            issuer: vec!["https://issuer.example.com".to_owned()],
            ..TokenValidationOptions::default()
        },
        scopes,
        jwks_url: None,
        remote_verify: Some(VerifyAccessTokenRemote {
            introspect_url,
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
            force: true,
        }),
    }
}

fn signed_hs256_token(kid: &str, claims: serde_json::Value) -> (String, Jwk) {
    let mut jwk = Jwk::generate_oct_key(32).expect("key should generate");
    if !kid.is_empty() {
        jwk.set_key_id(kid);
    }
    jwk.set_algorithm("HS256");
    let signer = Hs256.signer_from_jwk(&jwk).expect("signer should build");
    let token = encode_jwt("HS256", kid, claims, |payload, header| {
        jwt::encode_with_signer(payload, header, &signer)
    });
    (token, jwk)
}

fn signed_asymmetric_token(algorithm: &str, kid: &str) -> (String, Jwk) {
    let claims = json!({
        "sub": "user-123",
        "email": "test@example.com"
    });
    match algorithm {
        "RS256" => {
            let mut jwk = Jwk::generate_rsa_key(2048).expect("rsa key should generate");
            jwk.set_key_id(kid);
            jwk.set_algorithm("RS256");
            let signer = Rs256
                .signer_from_jwk(&jwk)
                .expect("rsa signer should build");
            let token = encode_jwt("RS256", kid, claims, |payload, header| {
                jwt::encode_with_signer(payload, header, &signer)
            });
            (token, jwk)
        }
        "ES256" => {
            let mut jwk = Jwk::generate_ec_key(P_256).expect("ec key should generate");
            jwk.set_key_id(kid);
            jwk.set_algorithm("ES256");
            let signer = Es256.signer_from_jwk(&jwk).expect("ec signer should build");
            let token = encode_jwt("ES256", kid, claims, |payload, header| {
                jwt::encode_with_signer(payload, header, &signer)
            });
            (token, jwk)
        }
        "EdDSA" => {
            let mut jwk = Jwk::generate_ed_key(Ed25519).expect("ed key should generate");
            jwk.set_key_id(kid);
            jwk.set_algorithm("EdDSA");
            let signer = Eddsa
                .signer_from_jwk(&jwk)
                .expect("eddsa signer should build");
            let token = encode_jwt("EdDSA", kid, claims, |payload, header| {
                jwt::encode_with_signer(payload, header, &signer)
            });
            (token, jwk)
        }
        other => panic!("unsupported test algorithm {other}"),
    }
}

fn encode_jwt<F>(algorithm: &str, kid: &str, claims: serde_json::Value, encode: F) -> String
where
    F: FnOnce(&JwtPayload, &JwsHeader) -> Result<String, josekit::JoseError>,
{
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(algorithm);
    if !kid.is_empty() {
        header.set_key_id(kid);
    }

    let mut payload = JwtPayload::new();
    for (key, value) in claims.as_object().expect("claims should be an object") {
        payload
            .set_claim(key, Some(value.clone()))
            .expect("claim should set");
    }

    encode(&payload, &header).expect("token should sign")
}

#[tokio::test]
async fn social_provider_default_revoke_token_returns_unsupported_error() {
    let provider: Box<dyn SocialOAuthProvider> = Box::new(DefaultOnlySocialProvider);

    let error = provider
        .revoke_token("token-1".to_owned())
        .await
        .expect_err("default revoke should be unsupported");

    assert_eq!(
        error.to_string(),
        "invalid OAuth response: provider does not support token revocation"
    );
}

#[tokio::test]
async fn social_provider_default_refresh_error_does_not_leak_token() {
    let provider: Box<dyn SocialOAuthProvider> = Box::new(DefaultOnlySocialProvider);

    let error = provider
        .refresh_access_token("secret-refresh-token".to_owned())
        .await
        .expect_err("default refresh should be unsupported");

    assert!(!error.to_string().contains("secret-refresh-token"));
    assert_eq!(
        error.to_string(),
        "invalid OAuth response: provider does not support refresh tokens"
    );
}

#[tokio::test]
async fn social_provider_can_override_refresh_verify_and_revoke_token() {
    let provider = FakeSocialProvider {
        verify_id_token: true,
    };

    let refreshed = provider
        .refresh_access_token("refresh-1".to_owned())
        .await
        .expect("override should refresh");
    let verified = provider
        .verify_id_token(SocialIdTokenRequest {
            token: "id-token-1".to_owned(),
            nonce: Some("nonce-1".to_owned()),
            ..SocialIdTokenRequest::default()
        })
        .await
        .expect("override should verify");
    provider
        .revoke_token("token-1".to_owned())
        .await
        .expect("override should revoke");

    assert_eq!(
        refreshed.access_token.as_deref(),
        Some("refreshed-refresh-1")
    );
    assert!(verified);
}

#[derive(Debug, Clone, Default)]
struct FakeSocialProvider {
    verify_id_token: bool,
}

#[derive(Debug, Clone, Default)]
struct DefaultOnlySocialProvider;

impl SocialOAuthProvider for DefaultOnlySocialProvider {
    fn id(&self) -> &str {
        "default-only"
    }

    fn name(&self) -> &str {
        "Default Only"
    }

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions::default()
    }

    fn create_authorization_url(
        &self,
        _input: SocialAuthorizationUrlRequest,
    ) -> Result<url::Url, OAuthError> {
        url::Url::parse("https://provider.example.com/authorize").map_err(Into::into)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async { Ok(OAuth2Tokens::default()) })
    }

    fn get_user_info(
        &self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async { Ok(None) })
    }
}

impl SocialOAuthProvider for FakeSocialProvider {
    fn id(&self) -> &str {
        "fake"
    }

    fn name(&self) -> &str {
        "Fake"
    }

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions::default()
    }

    fn create_authorization_url(
        &self,
        _input: SocialAuthorizationUrlRequest,
    ) -> Result<url::Url, OAuthError> {
        url::Url::parse("https://provider.example.com/authorize").map_err(Into::into)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async { Ok(OAuth2Tokens::default()) })
    }

    fn get_user_info(
        &self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async { Ok(None) })
    }

    fn verify_id_token(&self, _input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async move { Ok(self.verify_id_token) })
    }

    fn refresh_access_token(
        &self,
        refresh_token: String,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            Ok(OAuth2Tokens {
                access_token: Some(format!("refreshed-{refresh_token}")),
                ..OAuth2Tokens::default()
            })
        })
    }

    fn revoke_token(&self, token: String) -> SocialProviderFuture<'_, ()> {
        Box::pin(async move {
            if token == "token-1" {
                Ok(())
            } else {
                Err(OAuthError::InvalidResponse(format!(
                    "unexpected token `{token}`"
                )))
            }
        })
    }
}

struct JsonServer {
    url: String,
    body: std::sync::Arc<std::sync::Mutex<String>>,
    count: std::sync::Arc<std::sync::Mutex<usize>>,
    handle: Option<thread::JoinHandle<()>>,
}

struct RawServer {
    url: String,
    handle: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct JsonResponse {
    status: u16,
    body: serde_json::Value,
}

impl JsonResponse {
    fn ok(body: serde_json::Value) -> Self {
        Self { status: 200, body }
    }
}

impl JsonServer {
    fn spawn(response: serde_json::Value) -> Self {
        Self::spawn_many(vec![JsonResponse::ok(response)])
    }

    fn spawn_status(status: u16, response: serde_json::Value) -> Self {
        Self::spawn_many(vec![JsonResponse {
            status,
            body: response,
        }])
    }

    fn spawn_many(responses: Vec<JsonResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("local addr should exist")
        );
        let body = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let count = std::sync::Arc::new(std::sync::Mutex::new(0));
        let body_for_thread = std::sync::Arc::clone(&body);
        let count_for_thread = std::sync::Arc::clone(&count);
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("connection should accept");
                let mut buffer = [0; 8192];
                let read = stream.read(&mut buffer).expect("request should read");
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                if let Some((_, request_body)) = request.split_once("\r\n\r\n") {
                    *body_for_thread.lock().expect("body lock") = request_body.to_owned();
                }
                *count_for_thread.lock().expect("count lock") += 1;
                let response_body = response.body.to_string();
                let response = format!(
                    "HTTP/1.1 {} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.status,
                    response_body.len(),
                    response_body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
            }
        });

        Self {
            url,
            body,
            count,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn request_body(&self) -> String {
        self.body.lock().expect("body lock").clone()
    }

    fn request_count(&self) -> usize {
        *self.count.lock().expect("count lock")
    }
}

impl RawServer {
    fn spawn_status(status: u16, content_type: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("local addr should exist")
        );
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should accept");
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer).expect("request should read");
            let response = format!(
                "HTTP/1.1 {status} OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });
        Self {
            url,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }
}

impl Drop for JsonServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RawServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
