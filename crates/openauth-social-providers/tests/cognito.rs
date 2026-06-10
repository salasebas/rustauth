#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract};
use openauth_social_providers::advanced::cognito::{
    cognito, cognito_issuer, cognito_jwks_uri, CognitoAuthorizationUrlInput, CognitoOptions,
};
use openauth_social_providers::advanced::http::ProviderHttpClient;
use serde_json::json;
use time::OffsetDateTime;
use url::Url;

#[test]
fn cognito_derives_endpoints_from_clean_domain() {
    let provider = cognito(CognitoOptions::new(
        "client-id",
        "https://example.auth.us-east-1.amazoncognito.com",
        "us-east-1",
        "pool-id",
    ))
    .expect("provider should build");

    assert_eq!(provider.id(), "cognito");
    assert_eq!(provider.name(), "Cognito");
    assert_eq!(
        provider.authorization_endpoint(),
        "https://example.auth.us-east-1.amazoncognito.com/oauth2/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://example.auth.us-east-1.amazoncognito.com/oauth2/token"
    );
    assert_eq!(
        provider.user_info_endpoint(),
        "https://example.auth.us-east-1.amazoncognito.com/oauth2/userinfo"
    );
    assert_eq!(
        provider.expected_issuer(),
        "https://cognito-idp.us-east-1.amazonaws.com/pool-id"
    );
    assert_eq!(
        provider.jwks_endpoint(),
        "https://cognito-idp.us-east-1.amazonaws.com/pool-id/.well-known/jwks.json"
    );
}

#[test]
fn cognito_rejects_missing_domain_region_or_pool() {
    assert!(cognito(CognitoOptions::new("client-id", "", "us-east-1", "pool-id")).is_err());
    assert!(cognito(CognitoOptions::new(
        "client-id",
        "example.com",
        "",
        "pool-id"
    ))
    .is_err());
    assert!(cognito(CognitoOptions::new(
        "client-id",
        "example.com",
        "us-east-1",
        ""
    ))
    .is_err());
}

#[test]
fn cognito_authorization_url_uses_defaults_and_percent_twenty_scopes() {
    let mut options = CognitoOptions::new(
        ClientId::Multiple(vec![
            "primary-client".to_owned(),
            "mobile-client".to_owned(),
        ]),
        "example.auth.us-east-1.amazoncognito.com",
        "us-east-1",
        "pool-id",
    );
    options.scope = vec!["phone".to_owned()];
    options.prompt = Some("login".to_owned());

    let provider = cognito(options).expect("provider should build");
    let url = provider
        .create_authorization_url(CognitoAuthorizationUrlInput {
            state: "state-123".to_owned(),
            scopes: vec!["aws.cognito.signin.user.admin".to_owned()],
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            redirect_uri: "https://app.example.com/callback".to_owned(),
        })
        .expect("authorization URL should build");

    assert!(url.contains("scope=openid%20profile%20email%20phone%20aws.cognito.signin.user.admin"));
    let url = Url::parse(&url).expect("authorization URL should parse");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "client_id")
            .map(|(_, value)| value.into_owned()),
        Some("primary-client".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "prompt")
            .map(|(_, value)| value.into_owned()),
        Some("login".to_owned())
    );
    assert!(url
        .query_pairs()
        .any(|(key, value)| key == "code_challenge_method" && value == "S256"));
}

#[test]
fn cognito_authorization_url_honors_disable_default_scope_and_secret_requirement() {
    let mut options = CognitoOptions::new(
        "client-id",
        "example.auth.us-east-1.amazoncognito.com",
        "us-east-1",
        "pool-id",
    );
    options.disable_default_scope = true;

    let provider = cognito(options).expect("provider should build");
    let url = provider
        .create_authorization_url(CognitoAuthorizationUrlInput {
            state: "state-123".to_owned(),
            scopes: vec!["custom".to_owned()],
            redirect_uri: "https://app.example.com/callback".to_owned(),
            code_verifier: None,
        })
        .expect("authorization URL should build");
    let url = Url::parse(&url).expect("authorization URL should parse");

    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.into_owned()),
        Some("custom".to_owned())
    );

    let mut options = provider.options().clone();
    options.require_client_secret = true;
    let provider = cognito(options).expect("provider should build");
    assert!(provider
        .create_authorization_url(CognitoAuthorizationUrlInput {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            ..CognitoAuthorizationUrlInput::default()
        })
        .is_err());
}

#[tokio::test]
async fn cognito_get_user_info_maps_decoded_id_token_profile() {
    let provider = cognito(CognitoOptions::new(
        "client-id",
        "example.auth.us-east-1.amazoncognito.com",
        "us-east-1",
        "pool-id",
    ))
    .expect("provider should build");
    let id_token = unsigned_jwt(json!({
        "sub": "user-123",
        "email": "ada@example.com",
        "email_verified": true,
        "given_name": "Ada",
        "picture": "https://example.com/ada.png",
        "custom:tenant": "tenant-1"
    }));

    let info = provider
        .get_user_info(&OAuth2Tokens {
            id_token: Some(id_token),
            ..OAuth2Tokens::default()
        })
        .await
        .expect("profile should decode")
        .expect("profile should exist");

    assert_eq!(info.user.id, "user-123");
    assert_eq!(info.user.name.as_deref(), Some("Ada"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        info.user.image.as_deref(),
        Some("https://example.com/ada.png")
    );
    assert!(info.user.email_verified);
    assert_eq!(info.data.extra["custom:tenant"], "tenant-1");
}

#[test]
fn cognito_public_metadata_helpers_match_upstream_urls() {
    assert_eq!(
        cognito_issuer("us-west-2", "pool-id"),
        "https://cognito-idp.us-west-2.amazonaws.com/pool-id"
    );
    assert_eq!(
        cognito_jwks_uri("us-west-2", "pool-id"),
        "https://cognito-idp.us-west-2.amazonaws.com/pool-id/.well-known/jwks.json"
    );
}

#[tokio::test]
async fn cognito_userinfo_rejects_private_literal_ip_domain_by_default() {
    // A domain that resolves to a private literal IP derives a userinfo URL
    // (`https://10.0.0.5/oauth2/userinfo`) the default client must refuse.
    let provider = cognito(CognitoOptions::new(
        "client-id",
        "10.0.0.5",
        "us-east-1",
        "pool-id",
    ))
    .expect("provider should build");

    // No id_token, so the access-token userinfo HTTP path is exercised.
    let result = provider
        .get_user_info(&OAuth2Tokens {
            access_token: Some("access-token".to_owned()),
            ..OAuth2Tokens::default()
        })
        .await;

    assert!(matches!(result, Err(OAuthError::InvalidConfiguration(_))));
}

fn unsigned_jwt(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

#[test]
fn cognito_verify_id_token_accepts_complete_signed_token() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = test_provider();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (token, jwk) = signed_token(json!({
        "sub": "user-123",
        "aud": "client-id",
        "iss": cognito_issuer("us-east-1", "pool-id"),
        "nonce": "nonce-1",
        "iat": now,
        "exp": now + 3600
    }));
    let jwks = jwks_with_key(jwk)?;

    assert!(provider.verify_id_token_with_jwk_set(&token, Some("nonce-1"), &jwks)?);
    Ok(())
}

#[test]
fn cognito_verify_id_token_rejects_tokens_missing_standard_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = test_provider();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let base = json!({
        "sub": "user-123",
        "aud": "client-id",
        "iss": cognito_issuer("us-east-1", "pool-id"),
        "iat": now,
        "exp": now + 3600
    });

    // `iat` is required here because Cognito enforces an ID-token max age.
    for missing in ["sub", "aud", "iss", "exp", "iat"] {
        let mut claims = base.clone();
        claims
            .as_object_mut()
            .expect("claims object")
            .remove(missing);
        let (token, jwk) = signed_token(claims);
        let jwks = jwks_with_key(jwk)?;
        let verified = provider.verify_id_token_with_jwk_set(&token, None, &jwks);

        assert!(
            !matches!(verified, Ok(true)),
            "token missing `{missing}` must be rejected"
        );
    }
    Ok(())
}

fn test_provider() -> openauth_social_providers::advanced::cognito::CognitoProvider {
    cognito(CognitoOptions::new(
        "client-id",
        "example.auth.us-east-1.amazoncognito.com",
        "us-east-1",
        "pool-id",
    ))
    .expect("provider should build")
    .with_http_client(ProviderHttpClient::permissive())
}

fn signed_token(claims: serde_json::Value) -> (String, Jwk) {
    let kid = "cognito-test-key";
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

fn jwks_with_key(jwk: Jwk) -> Result<JwkSet, Box<dyn std::error::Error>> {
    Ok(JwkSet::from_bytes(
        json!({ "keys": [jwk] }).to_string().as_bytes(),
    )?)
}
