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
    client_credentials_token, create_authorization_code_request, create_authorization_url,
    create_client_credentials_token_request, create_refresh_access_token_request,
    generate_code_challenge, get_oauth2_tokens, get_primary_client_id, refresh_access_token,
    validate_token, verify_access_token, verify_jws_access_token, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientCredentialsGrant,
    ClientCredentialsTokenRequest, ClientId, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo,
    OAuthError, ProviderOptions, RefreshAccessTokenRequest, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
    TokenValidationOptions, VerifyAccessTokenOptions, VerifyAccessTokenRemote,
};
use serde_json::json;
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
        },
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
        },
    )
    .await
    .is_err());
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
        TokenValidationOptions::default()
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
        TokenValidationOptions::default()
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
        TokenValidationOptions::default()
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
async fn verify_jws_access_token_maps_azp_to_client_id() {
    let (token, jwk) = signed_hs256_token(
        "azp-key",
        json!({
            "sub": "user-123",
            "azp": "authorized-party"
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk] }));

    let payload = verify_jws_access_token(&token, &server.url(), TokenValidationOptions::default())
        .await
        .expect("jws access token should verify")
        .payload;

    assert_eq!(payload["client_id"], "authorized-party");
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
        "invalid OAuth response: provider does not support token revocation for token `token-1`"
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
    handle: Option<thread::JoinHandle<()>>,
}

impl JsonServer {
    fn spawn(response: serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("local addr should exist")
        );
        let body = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let body_for_thread = std::sync::Arc::clone(&body);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should accept");
            let mut buffer = [0; 8192];
            let read = stream.read(&mut buffer).expect("request should read");
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            if let Some((_, request_body)) = request.split_once("\r\n\r\n") {
                *body_for_thread.lock().expect("body lock") = request_body.to_owned();
            }
            let response_body = response.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        Self {
            url,
            body,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn request_body(&self) -> String {
        self.body.lock().expect("body lock").clone()
    }
}

impl Drop for JsonServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
