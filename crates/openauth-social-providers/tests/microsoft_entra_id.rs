#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::Jwk;
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::http::ValidationHttpClient;
use openauth_social_providers::microsoft_entra_id::{
    microsoft_entra_id, MicrosoftEntraIdAuthorizationCodeRequest,
    MicrosoftEntraIdAuthorizationUrlRequest, MicrosoftEntraIdOptions, MicrosoftEntraIdProfile,
};
use serde_json::json;
use time::OffsetDateTime;
use url::Url;

#[test]
fn microsoft_entra_provider_exposes_upstream_metadata_and_default_endpoints() {
    let provider = microsoft_entra_id(options_with_client_id("ms-client"));

    assert_eq!(provider.id(), "microsoft");
    assert_eq!(provider.name(), "Microsoft EntraID");
    assert_eq!(
        provider.authorization_endpoint(),
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    );
    assert_eq!(
        provider.jwks_endpoint(),
        "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    );
}

#[test]
fn microsoft_entra_provider_derives_tenant_and_custom_authority_endpoints() {
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        tenant_id: Some("12345678-1234-1234-1234-123456789012".to_owned()),
        authority: Some("https://tenant.ciamlogin.com/".to_owned()),
        ..options_with_client_id("ms-client")
    });

    assert_eq!(
        provider.authorization_endpoint(),
        "https://tenant.ciamlogin.com/12345678-1234-1234-1234-123456789012/oauth2/v2.0/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://tenant.ciamlogin.com/12345678-1234-1234-1234-123456789012/oauth2/v2.0/token"
    );
}

#[test]
fn authorization_url_uses_microsoft_defaults_options_and_pkce() {
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::Multiple(vec![
                "web-client".to_owned(),
                "native-client".to_owned(),
            ])),
            scope: vec!["Calendars.Read".to_owned()],
            prompt: Some("select_account".to_owned()),
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    });

    let url = provider
        .create_authorization_url(MicrosoftEntraIdAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            scopes: vec!["Mail.Read".to_owned()],
            login_hint: Some("ada@example.com".to_owned()),
        })
        .expect("authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
    );
    assert_eq!(query(&url, "client_id"), Some("web-client".to_owned()));
    assert_eq!(
        query(&url, "scope"),
        Some("openid profile email User.Read offline_access Calendars.Read Mail.Read".to_owned())
    );
    assert_eq!(query(&url, "prompt"), Some("select_account".to_owned()));
    assert_eq!(
        query(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
    assert_eq!(
        query(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query(&url, "code_challenge").is_some());
}

#[test]
fn authorization_url_allows_public_client_without_secret_and_can_disable_default_scope() {
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("public-client")),
            disable_default_scope: true,
            scope: vec!["custom.scope".to_owned()],
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    });

    let url = provider
        .create_authorization_url(MicrosoftEntraIdAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["extra.scope".to_owned()],
            ..MicrosoftEntraIdAuthorizationUrlRequest::default()
        })
        .expect("public client authorization URL should build");

    assert_eq!(query(&url, "client_id"), Some("public-client".to_owned()));
    assert_eq!(
        query(&url, "scope"),
        Some("custom.scope extra.scope".to_owned())
    );
}

#[test]
fn authorization_url_rejects_missing_client_id() {
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions::default());

    assert!(provider
        .create_authorization_url(MicrosoftEntraIdAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            ..MicrosoftEntraIdAuthorizationUrlRequest::default()
        })
        .is_err());
}

#[test]
fn authorization_code_and_refresh_requests_match_microsoft_token_contract() {
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("ms-client")),
            client_secret: Some("ms-secret".to_owned()),
            scope: vec!["Calendars.Read".to_owned()],
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    });

    let code_request = provider
        .authorization_code_request(MicrosoftEntraIdAuthorizationCodeRequest {
            code: "code-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            device_id: Some("device-1".to_owned()),
        })
        .expect("code request should build");
    assert_eq!(code_request.form_value("client_id"), Some("ms-client"));
    assert_eq!(code_request.form_value("client_secret"), Some("ms-secret"));
    assert_eq!(
        code_request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(code_request.form_value("device_id"), Some("device-1"));

    let refresh_request = provider
        .refresh_access_token_request("refresh-123")
        .expect("refresh request should build");
    assert_eq!(
        refresh_request.form_value("refresh_token"),
        Some("refresh-123")
    );
    assert_eq!(
        refresh_request.form_value("scope"),
        Some("openid profile email User.Read offline_access Calendars.Read")
    );
}

#[test]
fn microsoft_profile_maps_to_user_info_with_verified_email_fallbacks() {
    let profile = MicrosoftEntraIdProfile {
        sub: "ms-subject".to_owned(),
        name: Some("Microsoft User".to_owned()),
        email: Some("user@example.com".to_owned()),
        preferred_username: Some("user@tenant.example".to_owned()),
        picture: Some("https://graph.example.com/photo.jpg".to_owned()),
        email_verified: None,
        verified_primary_email: vec!["user@example.com".to_owned()],
        verified_secondary_email: Vec::new(),
        ..MicrosoftEntraIdProfile::default()
    };

    let user = profile.to_user_info();

    assert_eq!(user.id, "ms-subject");
    assert_eq!(user.name.as_deref(), Some("Microsoft User"));
    assert_eq!(user.email.as_deref(), Some("user@example.com"));
    assert_eq!(
        user.image.as_deref(),
        Some("https://graph.example.com/photo.jpg")
    );
    assert!(user.email_verified);

    let profile = MicrosoftEntraIdProfile {
        sub: "ms-subject".to_owned(),
        email: Some("preferred@example.com".to_owned()),
        email_verified: Some(false),
        verified_primary_email: vec!["preferred@example.com".to_owned()],
        ..MicrosoftEntraIdProfile::default()
    };

    assert!(!profile.to_user_info().email_verified);
}

#[test]
fn get_user_info_decodes_id_token_and_returns_none_without_id_token() {
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        disable_profile_photo: true,
        ..options_with_client_id("ms-client")
    });

    let info = provider
        .get_user_info_from_tokens(&OAuth2Tokens {
            id_token: Some(unsigned_jwt(json!({
                "sub": "ms-user",
                "name": "Ada Entra",
                "email": "ada@example.com",
                "picture": "https://example.com/ada.jpg",
                "email_verified": true
            }))),
            ..OAuth2Tokens::default()
        })
        .expect("id token should decode")
        .expect("profile should exist");

    assert_eq!(info.user.id, "ms-user");
    assert_eq!(info.user.name.as_deref(), Some("Ada Entra"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert!(info.user.email_verified);
    assert!(provider
        .get_user_info_from_tokens(&OAuth2Tokens::default())
        .expect("missing token should not error")
        .is_none());
}

#[tokio::test]
async fn verify_id_token_accepts_multiple_audiences_and_common_tenant_without_issuer() {
    let (tokens, jwk) = signed_tokens(vec![json!({
        "sub": "ms-user",
        "aud": "native-client",
        "iss": "https://login.microsoftonline.com/common/v2.0",
        "nonce": "nonce-123",
        "iat": OffsetDateTime::now_utc().unix_timestamp(),
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600
    })]);
    let token = &tokens[0];
    let server = JsonServer::spawn(json!({ "keys": [jwk] }), 2);
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::Multiple(vec![
                "web-client".to_owned(),
                "native-client".to_owned(),
            ])),
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    })
    .with_validation_http_client(ValidationHttpClient::permissive());

    assert!(provider
        .verify_id_token_with_jwks_url(token, Some("nonce-123"), &server.url())
        .await
        .expect("verification should run"));
    assert!(!provider
        .verify_id_token_with_jwks_url(token, Some("wrong-nonce"), &server.url())
        .await
        .expect("verification should run"));
}

#[tokio::test]
async fn verify_id_token_respects_disable_sign_in_and_specific_tenant_issuer() {
    let tenant = "tenant-123";
    let (tokens, valid_jwk) = signed_tokens(vec![
        json!({
            "sub": "ms-user",
            "aud": "web-client",
            "iss": format!("https://login.microsoftonline.com/{tenant}/v2.0"),
            "iat": OffsetDateTime::now_utc().unix_timestamp(),
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600
        }),
        json!({
            "sub": "ms-user",
            "aud": "web-client",
            "iss": "https://login.microsoftonline.com/wrong/v2.0",
            "iat": OffsetDateTime::now_utc().unix_timestamp(),
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600
        }),
    ]);
    let valid_token = &tokens[0];
    let wrong_issuer_token = &tokens[1];
    let server = JsonServer::spawn(json!({ "keys": [valid_jwk] }), 2);
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        tenant_id: Some(tenant.to_owned()),
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("web-client")),
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    })
    .with_validation_http_client(ValidationHttpClient::permissive());

    assert!(provider
        .verify_id_token_with_jwks_url(valid_token, None, &server.url())
        .await
        .expect("verification should run"));
    assert!(!provider
        .verify_id_token_with_jwks_url(wrong_issuer_token, None, &server.url())
        .await
        .expect("verification should run"));

    let disabled = microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("web-client")),
            disable_id_token_sign_in: true,
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    });
    assert!(!disabled
        .verify_id_token_with_jwks_url(valid_token, None, &server.url())
        .await
        .expect("verification should run"));
}

#[tokio::test]
async fn verify_id_token_rejects_tokens_missing_standard_claims() {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let tenant = "tenant-123";
    let base = json!({
        "sub": "ms-user",
        "aud": "web-client",
        "iss": format!("https://login.microsoftonline.com/{tenant}/v2.0"),
        "iat": now,
        "exp": now + 3600
    });
    let missing_claims = ["sub", "aud", "iss", "exp"];
    let token_claims = missing_claims
        .iter()
        .map(|missing| {
            let mut claims = base.clone();
            claims
                .as_object_mut()
                .expect("claims object")
                .remove(*missing);
            claims
        })
        .collect();
    let (tokens, jwk) = signed_tokens(token_claims);
    let server = JsonServer::spawn(json!({ "keys": [jwk] }), missing_claims.len());
    let provider = microsoft_entra_id(MicrosoftEntraIdOptions {
        tenant_id: Some(tenant.to_owned()),
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("web-client")),
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    })
    .with_validation_http_client(ValidationHttpClient::permissive());

    for (token, missing) in tokens.iter().zip(missing_claims) {
        assert!(
            !provider
                .verify_id_token_with_jwks_url(token, None, &server.url())
                .await
                .expect("verification should run"),
            "token missing `{missing}` must be rejected"
        );
    }
}

fn options_with_client_id(client_id: &str) -> MicrosoftEntraIdOptions {
    MicrosoftEntraIdOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from(client_id)),
            ..ProviderOptions::default()
        },
        ..MicrosoftEntraIdOptions::default()
    }
}

fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.into_owned())
}

fn unsigned_jwt(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

fn signed_tokens(claims: Vec<serde_json::Value>) -> (Vec<String>, Jwk) {
    let kid = "microsoft-test-key";
    let mut jwk = Jwk::generate_rsa_key(2048).expect("rsa key should generate");
    jwk.set_key_id(kid);
    jwk.set_algorithm("RS256");
    jwk.set_key_use("sig");

    let signer = Rs256
        .signer_from_jwk(&jwk)
        .expect("rsa signer should build");
    let tokens = claims
        .into_iter()
        .map(|claims| {
            let mut payload = JwtPayload::new();
            for (key, value) in claims.as_object().expect("claims should be an object") {
                payload
                    .set_claim(key, Some(value.clone()))
                    .expect("claim should set");
            }
            let mut header = JwsHeader::new();
            header.set_algorithm("RS256");
            header.set_key_id(kid);
            jwt::encode_with_signer(&payload, &header, &signer).expect("token should encode")
        })
        .collect();
    let mut public_jwk = jwk.to_public_key().expect("public jwk should export");
    public_jwk.set_key_id(kid);
    public_jwk.set_algorithm("RS256");
    public_jwk.set_key_use("sig");
    (tokens, public_jwk)
}

struct JsonServer {
    url: String,
}

impl JsonServer {
    fn spawn(body: serde_json::Value, request_count: usize) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("server should bind");
        let addr = listener.local_addr().expect("server address");
        std::thread::spawn(move || {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buffer);
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                std::io::Write::write_all(&mut stream, response.as_bytes())
                    .expect("response should write");
            }
        });
        Self {
            url: format!("http://{addr}/keys"),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }
}
