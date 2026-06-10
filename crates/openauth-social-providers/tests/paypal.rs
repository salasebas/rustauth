#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::advanced::paypal::{
    paypal, PayPalAuthorizationUrlRequest, PayPalEnvironment, PayPalOptions, PayPalProfile,
    PAYPAL_ISSUER, PAYPAL_LIVE_JWKS_ENDPOINT, PAYPAL_SANDBOX_JWKS_ENDPOINT,
};
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;

#[test]
fn paypal_provider_exposes_upstream_metadata_and_sandbox_endpoints() {
    let provider = paypal(paypal_options());

    assert_eq!(provider.id(), "paypal");
    assert_eq!(provider.name(), "PayPal");
    assert_eq!(
        provider.authorization_endpoint(),
        "https://www.sandbox.paypal.com/signin/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://api-m.sandbox.paypal.com/v1/oauth2/token"
    );
    assert_eq!(
        provider.user_info_endpoint(),
        "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo"
    );
}

#[test]
fn paypal_live_environment_uses_production_endpoints() {
    let provider = paypal(PayPalOptions {
        environment: PayPalEnvironment::Live,
        ..paypal_options()
    });

    assert_eq!(
        provider.authorization_endpoint(),
        "https://www.paypal.com/signin/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://api-m.paypal.com/v1/oauth2/token"
    );
    assert_eq!(
        provider.user_info_endpoint(),
        "https://api-m.paypal.com/v1/identity/oauth2/userinfo"
    );
}

#[test]
fn paypal_authorization_url_omits_scopes_and_keeps_prompt() {
    let mut options = paypal_options();
    options.oauth.scope = vec!["openid".to_owned(), "email".to_owned()];
    options.oauth.prompt = Some("login".to_owned());
    let provider = paypal(options);

    let url = provider
        .create_authorization_url(PayPalAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        })
        .expect("authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(provider.authorization_endpoint())
    );
    assert_eq!(query_value(&url, "scope"), None);
    assert_eq!(query_value(&url, "prompt"), Some("login".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("paypal-client".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
}

#[test]
fn paypal_authorization_url_requires_client_id_and_secret() {
    let provider = paypal(PayPalOptions::default());

    let error = provider
        .create_authorization_url(PayPalAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: None,
        })
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `client_id`"
    );

    let provider = paypal(PayPalOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("paypal-client")),
            ..ProviderOptions::default()
        },
        ..PayPalOptions::default()
    });

    let error = provider
        .create_authorization_url(PayPalAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: None,
        })
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `client_secret`"
    );
}

#[test]
fn paypal_token_requests_use_basic_auth_and_paypal_headers() {
    let provider = paypal(paypal_options());
    let request = provider
        .authorization_code_request("code-1", "https://app.example.com/auth/callback")
        .expect("request should build");

    assert_eq!(
        request.header("authorization"),
        basic_auth_header().as_deref()
    );
    assert_eq!(request.header("accept-language"), Some("en_US"));
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
}

#[test]
fn paypal_refresh_requests_use_basic_auth_and_paypal_headers() {
    let provider = paypal(paypal_options());
    let request = provider
        .refresh_access_token_request("refresh-1")
        .expect("request should build");

    assert_eq!(
        request.header("authorization"),
        basic_auth_header().as_deref()
    );
    assert_eq!(request.header("accept-language"), Some("en_US"));
    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
}

#[test]
fn paypal_profile_maps_to_user_info() {
    let profile = paypal_profile();

    let mapped = paypal(paypal_options()).map_profile(profile);

    assert_eq!(mapped.user.id, "paypal-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://example.com/ada.png")
    );
    assert!(mapped.user.email_verified);
    assert_eq!(mapped.data.payer_id.as_deref(), Some("payer-1"));
}

#[test]
fn paypal_id_token_metadata_matches_paypal_openid_configuration() {
    assert_eq!(PAYPAL_ISSUER, "https://www.paypal.com");
    assert_eq!(
        PAYPAL_SANDBOX_JWKS_ENDPOINT,
        "https://api-m.sandbox.paypal.com/v1/oauth2/certs"
    );
    assert_eq!(
        PAYPAL_LIVE_JWKS_ENDPOINT,
        "https://api-m.paypal.com/v1/oauth2/certs"
    );
}

#[tokio::test]
async fn paypal_verify_id_token_rejects_unsigned_jwt_by_default() -> Result<(), OAuthError> {
    let provider = paypal(paypal_options());
    let token = unsigned_jwt(json!({
        "sub": "paypal-user-1",
        "aud": "paypal-client",
        "iss": PAYPAL_ISSUER,
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600
    }));

    assert!(!provider.verify_id_token(&token, None).await?);
    Ok(())
}

#[tokio::test]
async fn paypal_verify_id_token_accepts_signed_token_with_expected_claims() -> Result<(), OAuthError>
{
    let (token, jwk) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    let jwks = jwks_with_keys(vec![jwk]);
    let provider = paypal(paypal_options());

    assert!(provider.verify_id_token_with_jwk_set(&token, Some("nonce-1"), &jwks)?);
    Ok(())
}

#[tokio::test]
async fn paypal_verify_id_token_rejects_unsigned_invalid_claims_and_wrong_keys(
) -> Result<(), OAuthError> {
    let unsigned = unsigned_jwt(json!({
        "sub": "paypal-user-1",
        "aud": "paypal-client",
        "iss": PAYPAL_ISSUER,
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600
    }));
    let (_, jwk) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    let jwks = jwks_with_keys(vec![jwk]);
    let provider = paypal(paypal_options());
    assert!(!provider.verify_id_token_with_jwk_set(&unsigned, Some("nonce-1"), &jwks)?);

    let (wrong_audience, _) = signed_paypal_id_token(
        "other-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    assert!(!provider.verify_id_token_with_jwk_set(&wrong_audience, Some("nonce-1"), &jwks)?);

    let (wrong_issuer, _) = signed_paypal_id_token(
        "paypal-client",
        "https://issuer.example",
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    assert!(!provider.verify_id_token_with_jwk_set(&wrong_issuer, Some("nonce-1"), &jwks)?);

    let (wrong_nonce, _) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    assert!(!provider.verify_id_token_with_jwk_set(&wrong_nonce, Some("different"), &jwks)?);

    let (expired, _) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        -60,
        0,
        true,
    );
    assert!(!provider.verify_id_token_with_jwk_set(&expired, Some("nonce-1"), &jwks)?);

    let (future_iat, _) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        120,
        true,
    );
    assert!(!provider.verify_id_token_with_jwk_set(&future_iat, Some("nonce-1"), &jwks)?);

    let (missing_kid, _) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        false,
    );
    assert!(!provider.verify_id_token_with_jwk_set(&missing_kid, Some("nonce-1"), &jwks)?);

    let (wrong_key_token, _) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    let (_, wrong_key) = signed_paypal_id_token(
        "paypal-client",
        PAYPAL_ISSUER,
        Some("nonce-1"),
        3600,
        0,
        true,
    );
    let wrong_key_jwks = jwks_with_keys(vec![wrong_key]);
    assert!(!provider.verify_id_token_with_jwk_set(
        &wrong_key_token,
        Some("nonce-1"),
        &wrong_key_jwks
    )?);

    Ok(())
}

#[tokio::test]
async fn paypal_verify_id_token_rejects_tokens_missing_standard_claims() -> Result<(), OAuthError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let base = json!({
        "sub": "paypal-user-1",
        "aud": "paypal-client",
        "iss": PAYPAL_ISSUER,
        "exp": now + 3600,
        "iat": now
    });
    let provider = paypal(paypal_options());

    for missing in ["sub", "aud", "iss", "exp"] {
        let mut claims = base.clone();
        claims
            .as_object_mut()
            .expect("claims object")
            .remove(missing);
        let (token, jwk) = signed_paypal_id_token_from_claims(claims);
        let jwks = jwks_with_keys(vec![jwk]);

        assert!(
            !provider.verify_id_token_with_jwk_set(&token, None, &jwks)?,
            "token missing `{missing}` must be rejected"
        );
    }
    Ok(())
}

#[tokio::test]
async fn paypal_verify_id_token_returns_false_when_disabled_or_client_id_missing(
) -> Result<(), OAuthError> {
    let token = unsigned_jwt(json!({ "sub": "paypal-user-1" }));

    let disabled = paypal(PayPalOptions {
        oauth: ProviderOptions {
            disable_id_token_sign_in: true,
            ..paypal_options().oauth
        },
        ..paypal_options()
    });
    assert!(!disabled.verify_id_token(&token, None).await?);

    let missing_client = paypal(PayPalOptions {
        oauth: ProviderOptions::default(),
        ..PayPalOptions::default()
    });
    assert!(!missing_client.verify_id_token(&token, None).await?);

    Ok(())
}

#[tokio::test]
async fn paypal_verify_id_token_uses_custom_verifier_when_configured() {
    let provider = paypal(PayPalOptions {
        verify_id_token: Some(Arc::new(|token, nonce| {
            Box::pin(
                async move { Ok(token == "id-token-1" && nonce.as_deref() == Some("nonce-1")) },
            )
        })),
        ..paypal_options()
    });

    assert!(provider
        .verify_id_token("id-token-1", Some("nonce-1"))
        .await
        .expect("custom verifier should run"));
    assert!(!provider
        .verify_id_token("id-token-1", Some("wrong"))
        .await
        .expect("custom verifier should reject wrong nonce"));
}

#[tokio::test]
async fn paypal_get_user_info_returns_none_without_access_token() {
    let provider = paypal(paypal_options());

    let info = provider
        .get_user_info(&OAuth2Tokens::default())
        .await
        .expect("missing access token is not a transport error");

    assert!(info.is_none());
}

fn paypal_options() -> PayPalOptions {
    PayPalOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("paypal-client")),
            client_secret: Some("paypal-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..PayPalOptions::default()
    }
}

fn paypal_profile() -> PayPalProfile {
    PayPalProfile {
        user_id: "paypal-user-1".to_owned(),
        name: "Ada Lovelace".to_owned(),
        given_name: "Ada".to_owned(),
        family_name: "Lovelace".to_owned(),
        middle_name: None,
        picture: Some("https://example.com/ada.png".to_owned()),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: Some("en_US".to_owned()),
        phone_number: None,
        address: None,
        verified_account: Some(true),
        account_type: Some("personal".to_owned()),
        age_range: None,
        payer_id: Some("payer-1".to_owned()),
        extra: Default::default(),
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn basic_auth_header() -> Option<String> {
    Some(format!(
        "Basic {}",
        STANDARD.encode("paypal-client:paypal-secret")
    ))
}

fn unsigned_jwt(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

fn signed_paypal_id_token(
    audience: &str,
    issuer: &str,
    nonce: Option<&str>,
    expires_in_seconds: i64,
    issued_at_offset_seconds: i64,
    include_kid: bool,
) -> (String, Jwk) {
    let kid = "paypal-test-key";
    let mut jwk = Jwk::generate_rsa_key(2048).expect("rsa key should generate");
    jwk.set_key_id(kid);
    jwk.set_algorithm("RS256");
    jwk.set_key_use("sig");
    let signer = Rs256
        .signer_from_jwk(&jwk)
        .expect("rsa signer should build");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut payload = JwtPayload::new();
    payload
        .set_claim("sub", Some(json!("paypal-user-1")))
        .expect("sub claim");
    payload
        .set_claim("aud", Some(json!(audience)))
        .expect("aud claim");
    payload
        .set_claim("iss", Some(json!(issuer)))
        .expect("iss claim");
    payload
        .set_claim("iat", Some(json!(now + issued_at_offset_seconds)))
        .expect("iat claim");
    payload
        .set_claim("exp", Some(json!(now + expires_in_seconds)))
        .expect("exp claim");
    if let Some(nonce) = nonce {
        payload
            .set_claim("nonce", Some(json!(nonce)))
            .expect("nonce claim");
    }
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    if include_kid {
        header.set_key_id(kid);
    }
    let token = jwt::encode_with_signer(&payload, &header, &signer).expect("token should encode");
    let mut public_jwk = jwk.to_public_key().expect("public jwk should export");
    public_jwk.set_key_id(kid);
    public_jwk.set_algorithm("RS256");
    public_jwk.set_key_use("sig");
    (token, public_jwk)
}

fn jwks_with_keys(keys: Vec<Jwk>) -> JwkSet {
    let bytes = json!({ "keys": keys }).to_string();
    JwkSet::from_bytes(bytes.as_bytes()).expect("jwks should parse")
}

fn signed_paypal_id_token_from_claims(claims: serde_json::Value) -> (String, Jwk) {
    let kid = "paypal-test-key";
    let mut jwk = Jwk::generate_rsa_key(2048).expect("rsa key should generate");
    jwk.set_key_id(kid);
    jwk.set_algorithm("RS256");
    jwk.set_key_use("sig");
    let signer = Rs256
        .signer_from_jwk(&jwk)
        .expect("rsa signer should build");
    let mut payload = JwtPayload::new();
    for (key, value) in claims.as_object().expect("claims should be an object") {
        payload
            .set_claim(key, Some(value.clone()))
            .expect("claim should set");
    }
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id(kid);
    let token = jwt::encode_with_signer(&payload, &header, &signer).expect("token should encode");
    let mut public_jwk = jwk.to_public_key().expect("public jwk should export");
    public_jwk.set_key_id(kid);
    public_jwk.set_algorithm("RS256");
    public_jwk.set_key_use("sig");
    (token, public_jwk)
}
