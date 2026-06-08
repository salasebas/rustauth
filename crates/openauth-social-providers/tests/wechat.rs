#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, ProviderOptions};
use openauth_social_providers::wechat::{
    wechat, WeChatAuthorizationUrlRequest, WeChatLang, WeChatProfile, WeChatProvider,
    WeChatProviderOptions, WECHAT_AUTHORIZATION_ENDPOINT, WECHAT_ID, WECHAT_NAME,
};
use serde_json::json;

#[test]
fn wechat_provider_exposes_upstream_metadata() {
    let provider = WeChatProvider::new(WeChatProviderOptions {
        oauth: provider_options(),
        ..WeChatProviderOptions::default()
    });

    assert_eq!(provider.id(), WECHAT_ID);
    assert_eq!(provider.name(), WECHAT_NAME);
}

#[test]
fn authorization_url_uses_wechat_oauth_shape_and_defaults() {
    let provider = wechat(provider_options());

    let url = provider
        .create_authorization_url(WeChatAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/wechat/callback".to_owned(),
            scopes: Vec::new(),
        })
        .expect("authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(WECHAT_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(query_value(&url, "appid"), Some("wechat-client".to_owned()));
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/wechat/callback".to_owned())
    );
    assert_eq!(query_value(&url, "scope"), Some("snsapi_login".to_owned()));
    assert_eq!(query_value(&url, "lang"), Some("cn".to_owned()));
    assert_eq!(url.fragment(), Some("wechat_redirect"));
}

#[test]
fn authorization_url_merges_scopes_and_can_disable_default_scope() {
    let provider = wechat(ProviderOptions {
        scope: vec!["configured".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(WeChatAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/wechat/callback".to_owned(),
            scopes: vec!["requested".to_owned()],
        })
        .expect("authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("snsapi_login,configured,requested".to_owned())
    );

    let provider = wechat(ProviderOptions {
        disable_default_scope: true,
        scope: vec!["configured".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(WeChatAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/wechat/callback".to_owned(),
            scopes: vec!["requested".to_owned()],
        })
        .expect("authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("configured,requested".to_owned())
    );
}

#[test]
fn authorization_url_rejects_empty_state() {
    let provider = wechat(provider_options());

    let error = provider
        .create_authorization_url(WeChatAuthorizationUrlRequest {
            state: String::new(),
            redirect_uri: "https://app.example.com/auth/wechat/callback".to_owned(),
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert!(error
        .as_deref()
        .is_some_and(|message| message.contains("authorization state")));
}

#[test]
fn authorization_url_rejects_invalid_redirect_uri_without_override() {
    let provider = wechat(provider_options());

    let error = provider
        .create_authorization_url(WeChatAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "notaurl".to_owned(),
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert!(error
        .as_deref()
        .is_some_and(|message| message.contains("OAuth URL")));
}

#[test]
fn authorization_url_uses_redirect_override_and_english_lang() {
    let provider = WeChatProvider::new(WeChatProviderOptions {
        oauth: ProviderOptions {
            redirect_uri: Some("https://auth.example.com/wechat/callback".to_owned()),
            ..provider_options()
        },
        lang: Some(WeChatLang::En),
    });

    let url = provider
        .create_authorization_url(WeChatAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/wechat/callback".to_owned(),
            scopes: Vec::new(),
        })
        .expect("authorization URL should build");

    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/wechat/callback".to_owned())
    );
    assert_eq!(query_value(&url, "lang"), Some("en".to_owned()));
}

#[test]
fn token_and_refresh_urls_use_wechat_get_parameters() {
    let provider = wechat(provider_options());

    let token_url = provider
        .authorization_code_url("code-1")
        .expect("token URL should build");
    assert_eq!(
        query_value(&token_url, "appid"),
        Some("wechat-client".to_owned())
    );
    assert_eq!(
        query_value(&token_url, "secret"),
        Some("wechat-secret".to_owned())
    );
    assert_eq!(query_value(&token_url, "code"), Some("code-1".to_owned()));
    assert_eq!(
        query_value(&token_url, "grant_type"),
        Some("authorization_code".to_owned())
    );

    let refresh_url = provider
        .refresh_access_token_url("refresh-1")
        .expect("refresh URL should build");
    assert_eq!(
        query_value(&refresh_url, "appid"),
        Some("wechat-client".to_owned())
    );
    assert_eq!(
        query_value(&refresh_url, "refresh_token"),
        Some("refresh-1".to_owned())
    );
    assert_eq!(
        query_value(&refresh_url, "grant_type"),
        Some("refresh_token".to_owned())
    );
}

#[test]
fn token_and_refresh_urls_require_configured_credentials() {
    let missing_client_id = wechat(ProviderOptions {
        client_secret: Some("wechat-secret".to_owned()),
        ..ProviderOptions::default()
    });
    assert!(missing_client_id.authorization_code_url("code-1").is_err());
    assert!(missing_client_id
        .refresh_access_token_url("refresh-1")
        .is_err());

    let missing_secret = wechat(ProviderOptions {
        client_id: Some(ClientId::from("wechat-client")),
        ..ProviderOptions::default()
    });
    assert!(missing_secret.authorization_code_url("code-1").is_err());
    assert!(missing_secret
        .refresh_access_token_url("refresh-1")
        .is_err());
}

#[test]
fn user_info_url_requires_openid_from_raw_token_payload() {
    let provider = wechat(provider_options());

    let without_openid = OAuth2Tokens {
        access_token: Some("access-1".to_owned()),
        raw: json!({ "unionid": "union-1" }),
        ..OAuth2Tokens::default()
    };
    assert_eq!(
        provider
            .user_info_url(&without_openid)
            .expect("URL building should not fail without openid"),
        None
    );

    let with_openid = OAuth2Tokens {
        access_token: Some("access-1".to_owned()),
        raw: json!({ "openid": "openid-1" }),
        ..OAuth2Tokens::default()
    };
    let url = provider
        .user_info_url(&with_openid)
        .expect("URL should build")
        .expect("openid should produce a URL");

    assert_eq!(
        query_value(&url, "access_token"),
        Some("access-1".to_owned())
    );
    assert_eq!(query_value(&url, "openid"), Some("openid-1".to_owned()));
    assert_eq!(query_value(&url, "lang"), Some("zh_CN".to_owned()));
}

#[test]
fn maps_wechat_profile_to_oauth_user_info() {
    let mapped = WeChatProvider::map_profile(WeChatProfile {
        openid: "openid-1".to_owned(),
        nickname: "Ada".to_owned(),
        headimgurl: "https://img.example.com/ada.jpg".to_owned(),
        privilege: vec!["chinaunicom".to_owned()],
        unionid: Some("union-1".to_owned()),
        extra: Default::default(),
    });

    assert_eq!(mapped.user.id, "union-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada"));
    assert_eq!(mapped.user.email, None);
    assert!(!mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://img.example.com/ada.jpg")
    );
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("wechat-client")),
        client_secret: Some("wechat-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
