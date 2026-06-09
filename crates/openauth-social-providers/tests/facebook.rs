#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, ProviderOptions};
use openauth_social_providers::advanced::facebook::{
    FacebookOptions, FacebookPicture, FacebookPictureData, FacebookProfile, FacebookProvider,
    FACEBOOK_LIMITED_LOGIN_ISSUER,
};
use serde_json::json;
use time::OffsetDateTime;

#[test]
fn facebook_authorization_url_uses_upstream_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: provider_options(),
        config_id: Some("login-config".to_owned()),
        ..FacebookOptions::default()
    });

    let url = provider.create_authorization_url(
        "state-value",
        ["business_management".to_owned()],
        "https://app.example.com/callback",
        Some("user@example.com"),
    )?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://www.facebook.com/v24.0/dialog/oauth")
    );
    assert_eq!(query(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(query(&url, "client_id"), Some("fb-web".to_owned()));
    assert_eq!(
        query(&url, "redirect_uri"),
        Some("https://app.example.com/callback".to_owned())
    );
    assert_eq!(query(&url, "state"), Some("state-value".to_owned()));
    assert_eq!(
        query(&url, "scope"),
        Some("email public_profile pages_show_list business_management".to_owned())
    );
    assert_eq!(
        query(&url, "login_hint"),
        Some("user@example.com".to_owned())
    );
    assert_eq!(query(&url, "config_id"), Some("login-config".to_owned()));
    Ok(())
}

#[test]
fn facebook_authorization_url_rejects_missing_required_credentials() {
    let provider = FacebookProvider::new(FacebookOptions::default());

    let result = provider.create_authorization_url(
        "state",
        Vec::<String>::new(),
        "https://app/callback",
        None,
    );

    assert!(result.is_err());
}

#[test]
fn facebook_authorization_url_can_disable_default_scopes() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: ProviderOptions {
            disable_default_scope: true,
            ..provider_options()
        },
        ..FacebookOptions::default()
    });

    let url = provider.create_authorization_url(
        "state",
        ["custom_scope".to_owned()],
        "https://app.example.com/callback",
        None,
    )?;

    assert_eq!(
        query(&url, "scope"),
        Some("pages_show_list custom_scope".to_owned())
    );
    Ok(())
}

#[test]
fn facebook_profile_mapping_matches_graph_profile_behavior() {
    let provider = FacebookProvider::new(FacebookOptions::default());
    let profile = FacebookProfile {
        id: "123".to_owned(),
        name: "Ada Lovelace".to_owned(),
        email: Some("ada@example.com".to_owned()),
        email_verified: None,
        picture: FacebookPicture {
            data: FacebookPictureData {
                height: 100,
                is_silhouette: false,
                url: "https://cdn.example.com/ada.png".to_owned(),
                width: 100,
            },
        },
    };

    let info = provider.user_info_from_profile(profile);

    assert_eq!(info.user.id, "123");
    assert_eq!(info.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        info.user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(!info.user.email_verified);
}

#[test]
fn facebook_limited_login_id_token_maps_to_user_with_unverified_email(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions::default());
    let token = unsigned_jwt(json!({
        "sub": "limited-user",
        "email": "limited@example.com",
        "name": "Limited User",
        "picture": "https://cdn.example.com/limited.png"
    }))?;

    let info = provider
        .user_info_from_id_token(&token)?
        .ok_or("valid id token payload")?;

    assert_eq!(info.user.id, "limited-user");
    assert_eq!(info.user.email.as_deref(), Some("limited@example.com"));
    assert_eq!(
        info.user.image.as_deref(),
        Some("https://cdn.example.com/limited.png")
    );
    assert!(!info.user.email_verified);
    Ok(())
}

#[test]
fn facebook_user_info_url_extends_default_fields() -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions {
        fields: vec!["first_name".to_owned(), "last_name".to_owned()],
        ..FacebookOptions::default()
    });

    let url = provider.user_info_url()?;

    assert_eq!(
        query(&url, "fields"),
        Some("id,name,email,picture,first_name,last_name".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn facebook_verify_id_token_rejects_opaque_access_tokens() {
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: provider_options(),
        ..FacebookOptions::default()
    });

    assert!(!provider.verify_id_token("opaque-token", None).await);
}

#[test]
fn facebook_verify_id_token_accepts_limited_login_jwt_via_jwks(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: provider_options(),
        ..FacebookOptions::default()
    });
    let (token, jwk) =
        signed_limited_login_jwt("fb-web", FACEBOOK_LIMITED_LOGIN_ISSUER, Some("n"))?;
    let jwks = jwks_with_key(jwk)?;

    assert!(provider.verify_id_token_with_jwk_set(&token, Some("n"), &jwks));
    Ok(())
}

#[test]
fn facebook_verify_id_token_rejects_wrong_nonce_issuer_and_disabled_sign_in(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: provider_options(),
        ..FacebookOptions::default()
    });
    let (token, jwk) =
        signed_limited_login_jwt("fb-web", FACEBOOK_LIMITED_LOGIN_ISSUER, Some("n"))?;
    let jwks = jwks_with_key(jwk)?;
    assert!(!provider.verify_id_token_with_jwk_set(&token, Some("different"), &jwks));

    let (other_issuer, jwk) =
        signed_limited_login_jwt("fb-web", "https://evil.example", Some("n"))?;
    let other_jwks = jwks_with_key(jwk)?;
    assert!(!provider.verify_id_token_with_jwk_set(&other_issuer, Some("n"), &other_jwks));

    let disabled = FacebookProvider::new(FacebookOptions {
        oauth: ProviderOptions {
            disable_id_token_sign_in: true,
            ..provider_options()
        },
        ..FacebookOptions::default()
    });
    assert!(!disabled.verify_id_token_with_jwk_set(&token, Some("n"), &jwks));
    Ok(())
}

#[tokio::test]
async fn facebook_get_user_info_returns_none_when_access_token_is_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions::default());
    let tokens = OAuth2Tokens::default();

    let info = provider.get_user_info(&tokens).await?;

    assert!(info.is_none());
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::Multiple(vec![
            "fb-web".to_owned(),
            "fb-mobile".to_owned(),
        ])),
        client_secret: Some("fb-secret".to_owned()),
        scope: vec!["pages_show_list".to_owned()],
        ..ProviderOptions::default()
    }
}

fn query(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn unsigned_jwt(payload: serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({ "alg": "none" }))?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    Ok(format!("{header}.{payload}."))
}

#[test]
fn facebook_verify_id_token_accepts_complete_signed_token_with_standard_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: provider_options(),
        ..FacebookOptions::default()
    });
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (token, jwk) = signed_token(json!({
        "sub": "limited-user",
        "aud": "fb-web",
        "iss": FACEBOOK_LIMITED_LOGIN_ISSUER,
        "nonce": "nonce-1",
        "exp": now + 3600,
        "iat": now
    }));
    let jwks = jwks_with_key(jwk)?;

    assert!(provider.verify_id_token_with_jwk_set(&token, Some("nonce-1"), &jwks));
    Ok(())
}

#[test]
fn facebook_verify_id_token_rejects_signed_tokens_missing_standard_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = FacebookProvider::new(FacebookOptions {
        oauth: provider_options(),
        ..FacebookOptions::default()
    });
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let base = json!({
        "sub": "limited-user",
        "aud": "fb-web",
        "iss": FACEBOOK_LIMITED_LOGIN_ISSUER,
        "exp": now + 3600,
        "iat": now
    });

    for missing in ["sub", "aud", "iss", "exp"] {
        let mut claims = base.clone();
        claims
            .as_object_mut()
            .expect("claims object")
            .remove(missing);
        let (token, jwk) = signed_token(claims);
        let jwks = jwks_with_key(jwk)?;

        assert!(
            !provider.verify_id_token_with_jwk_set(&token, None, &jwks),
            "token missing `{missing}` must be rejected"
        );
    }
    Ok(())
}

fn signed_token(claims: serde_json::Value) -> (String, Jwk) {
    let kid = "facebook-test-key";
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

fn signed_limited_login_jwt(
    audience: &str,
    issuer: &str,
    nonce: Option<&str>,
) -> Result<(String, Jwk), Box<dyn std::error::Error>> {
    let kid = "facebook-test-key";
    let mut jwk = Jwk::generate_rsa_key(2048)?;
    jwk.set_key_id(kid);
    jwk.set_algorithm("RS256");
    jwk.set_key_use("sig");

    let signer = Rs256.signer_from_jwk(&jwk)?;
    let mut payload = JwtPayload::new();
    payload.set_claim("aud", Some(json!(audience)))?;
    payload.set_claim("iss", Some(json!(issuer)))?;
    payload.set_claim("sub", Some(json!("limited-user")))?;
    if let Some(nonce) = nonce {
        payload.set_claim("nonce", Some(json!(nonce)))?;
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    payload.set_claim("exp", Some(json!(now + 3600)))?;

    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id(kid);
    let token = jwt::encode_with_signer(&payload, &header, &signer)?;

    let mut public_jwk = jwk.to_public_key()?;
    public_jwk.set_key_id(kid);
    public_jwk.set_algorithm("RS256");
    public_jwk.set_key_use("sig");
    Ok((token, public_jwk))
}

fn jwks_with_key(jwk: Jwk) -> Result<JwkSet, Box<dyn std::error::Error>> {
    Ok(JwkSet::from_bytes(
        json!({ "keys": [jwk] }).to_string().as_bytes(),
    )?)
}
