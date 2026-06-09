#![allow(clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use josekit::jwk::Jwk;
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::advanced::apple::{
    apple, AppleName, AppleNonConformUser, AppleOptions,
};
use openauth_social_providers::advanced::http::ValidationHttpClient;
use serde_json::{json, Value};
use time::OffsetDateTime;

#[test]
fn apple_provider_builds_authorization_url_with_upstream_defaults() {
    let provider = apple(options_with_client_id(ClientId::Multiple(vec![
        "apple-web".to_owned(),
        "apple-ios".to_owned(),
    ])));

    let url = provider
        .create_authorization_url(
            "state-123",
            ["extra"].into_iter().map(str::to_owned),
            "https://app.example.com/callback",
        )
        .expect("authorization url should build");

    assert_eq!(provider.id(), "apple");
    assert_eq!(provider.name(), "Apple");
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://appleid.apple.com/auth/authorize")
    );
    assert_eq!(query(&url, "client_id"), Some("apple-web".to_owned()));
    assert_eq!(
        query(&url, "redirect_uri"),
        Some("https://app.example.com/callback".to_owned())
    );
    assert_eq!(query(&url, "scope"), Some("email name extra".to_owned()));
    assert_eq!(query(&url, "response_mode"), Some("form_post".to_owned()));
    assert_eq!(
        query(&url, "response_type"),
        Some("code id_token".to_owned())
    );
}

#[test]
fn apple_provider_can_disable_default_scopes() {
    let mut options = options_with_client_id(ClientId::Single("apple-web".to_owned()));
    options.provider.disable_default_scope = true;
    options.provider.scope = vec!["openid".to_owned()];
    let provider = apple(options);

    let url = provider
        .create_authorization_url(
            "state-123",
            ["email"].into_iter().map(str::to_owned),
            "https://app.example.com/callback",
        )
        .expect("authorization url should build");

    assert_eq!(query(&url, "scope"), Some("openid email".to_owned()));
}

#[test]
fn apple_provider_rejects_empty_client_id_and_missing_secret() {
    let empty_client_id = apple(options_with_client_id(ClientId::Multiple(Vec::new())));
    assert!(empty_client_id
        .create_authorization_url(
            "state",
            std::iter::empty::<String>(),
            "https://app.example.com/callback",
        )
        .is_err());

    let mut options = options_with_client_id(ClientId::Single("apple-web".to_owned()));
    options.provider.client_secret = None;
    let missing_secret = apple(options);
    assert!(missing_secret
        .create_authorization_url(
            "state",
            std::iter::empty::<String>(),
            "https://app.example.com/callback",
        )
        .is_err());
}

#[test]
fn apple_provider_maps_id_token_profile_without_email_name_fallback() {
    let (token, _) = signed_token(
        "apple-key",
        json!({
            "sub": "001341.example.1128",
            "email": "user@privaterelay.appleid.com",
            "email_verified": true,
            "is_private_email": true,
            "real_user_status": 2
        }),
    );
    let provider = apple(options_with_client_id(ClientId::Single(
        "apple-web".to_owned(),
    )));

    let info = provider
        .get_user_info(
            &OAuth2Tokens {
                id_token: Some(token),
                ..OAuth2Tokens::default()
            },
            None,
        )
        .expect("profile should decode")
        .expect("id token should produce user info");

    assert_eq!(info.user.id, "001341.example.1128");
    assert_eq!(
        info.user.email.as_deref(),
        Some("user@privaterelay.appleid.com")
    );
    assert!(info.user.email_verified);
    assert_eq!(info.user.name.as_deref(), Some(""));
    assert_eq!(info.data.name.as_deref(), Some(""));
}

#[test]
fn apple_provider_prefers_non_conform_user_name() {
    let (token, _) = signed_token(
        "apple-key",
        json!({
            "sub": "001341.example.1129",
            "email": "user2@privaterelay.appleid.com",
            "email_verified": "true",
            "is_private_email": "true",
            "real_user_status": 2
        }),
    );
    let provider = apple(options_with_client_id(ClientId::Single(
        "apple-web".to_owned(),
    )));

    let info = provider
        .get_user_info(
            &OAuth2Tokens {
                id_token: Some(token),
                ..OAuth2Tokens::default()
            },
            Some(AppleNonConformUser {
                name: AppleName {
                    first_name: "Better".to_owned(),
                    last_name: "Auth".to_owned(),
                },
                email: "user2@privaterelay.appleid.com".to_owned(),
            }),
        )
        .expect("profile should decode")
        .expect("id token should produce user info");

    assert_eq!(info.user.name.as_deref(), Some("Better Auth"));
    assert!(info.user.email_verified);
    assert_eq!(info.data.is_private_email, Some(true));
}

#[test]
fn apple_provider_returns_none_without_id_token() {
    let provider = apple(options_with_client_id(ClientId::Single(
        "apple-web".to_owned(),
    )));

    let info = provider
        .get_user_info(&OAuth2Tokens::default(), None)
        .expect("missing id token is not an error");

    assert!(info.is_none());
}

#[tokio::test]
async fn apple_provider_verifies_id_token_with_local_jwks_and_nonce() {
    let (token, jwk) = signed_token(
        "apple-key",
        json!({
            "sub": "001341.example.verified",
            "iss": "https://appleid.apple.com",
            "aud": "apple-web",
            "nonce": "nonce-123",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "iat": OffsetDateTime::now_utc().unix_timestamp()
        }),
    );
    let server = JsonServer::spawn(json!({ "keys": [jwk] }));
    let provider = apple(options_with_client_id(ClientId::Single(
        "apple-web".to_owned(),
    )))
    .with_validation_http_client(ValidationHttpClient::permissive());

    assert!(provider
        .verify_id_token_with_jwks_url(&token, Some("nonce-123"), &server.url())
        .await
        .expect("token verification should run"));
    assert!(!provider
        .verify_id_token_with_jwks_url(&token, Some("wrong-nonce"), &server.url())
        .await
        .expect("token verification should run"));
}

#[tokio::test]
async fn apple_provider_rejects_id_tokens_missing_standard_claims() {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let base = json!({
        "sub": "001341.example.verified",
        "iss": "https://appleid.apple.com",
        "aud": "apple-web",
        "exp": now + 3600,
        "iat": now
    });
    let provider = apple(options_with_client_id(ClientId::Single(
        "apple-web".to_owned(),
    )))
    .with_validation_http_client(ValidationHttpClient::permissive());

    // `iat` is required here because Apple enforces an ID-token max age.
    for missing in ["sub", "iss", "aud", "exp", "iat"] {
        let mut claims = base.clone();
        claims
            .as_object_mut()
            .expect("claims object")
            .remove(missing);
        let (token, jwk) = signed_token("apple-key", claims);
        let server = JsonServer::spawn(json!({ "keys": [jwk] }));

        assert!(
            !provider
                .verify_id_token_with_jwks_url(&token, None, &server.url())
                .await
                .expect("token verification should run"),
            "token missing `{missing}` must be rejected"
        );
    }
}

fn options_with_client_id(client_id: ClientId) -> AppleOptions {
    AppleOptions {
        provider: ProviderOptions {
            client_id: Some(client_id),
            client_secret: Some("apple-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..AppleOptions::default()
    }
}

fn query(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.into_owned())
}

fn signed_token(kid: &str, claims: Value) -> (String, Jwk) {
    let mut jwk = Jwk::generate_rsa_key(2048).expect("key should generate");
    jwk.set_key_id(kid);
    jwk.set_algorithm("RS256");
    let signer = Rs256.signer_from_jwk(&jwk).expect("signer should build");
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_key_id(kid);
    header.set_algorithm("RS256");
    let mut payload = JwtPayload::new();
    if let Value::Object(map) = claims {
        for (key, value) in map {
            payload
                .set_claim(&key, Some(value))
                .expect("claim should set");
        }
    }
    let token = jwt::encode_with_signer(&payload, &header, &signer).expect("token should sign");
    (token, jwk)
}

struct JsonServer {
    address: String,
}

impl JsonServer {
    fn spawn(body: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("server should bind");
        let address = listener.local_addr().expect("server should expose address");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0; 2048];
                let _ = stream.read(&mut buffer);
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            address: format!("http://{address}/jwks"),
        }
    }

    fn url(&self) -> String {
        self.address.clone()
    }
}
