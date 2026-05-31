#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::http::ProviderHttpClient;
use openauth_social_providers::zoom::{
    zoom, ZoomAuthorizationCodeRequest, ZoomAuthorizationUrlRequest, ZoomOptions, ZoomProfile,
    ZoomProvider, ZOOM_AUTHORIZATION_ENDPOINT, ZOOM_ID, ZOOM_NAME, ZOOM_TOKEN_ENDPOINT,
};
use serde_json::json;

#[test]
fn zoom_provider_exposes_upstream_metadata() {
    let provider = zoom(zoom_options());

    assert_eq!((provider.id(), provider.name()), (ZOOM_ID, ZOOM_NAME));
}

#[test]
fn zoom_authorization_url_uses_pkce_by_default() -> Result<(), OAuthError> {
    let provider = zoom(zoom_options());

    let url = provider.create_authorization_url(ZoomAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
    })?;

    assert!(url.as_str().starts_with(ZOOM_AUTHORIZATION_ENDPOINT));
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("zoom-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
    Ok(())
}

#[test]
fn zoom_authorization_url_can_disable_pkce() -> Result<(), OAuthError> {
    let provider = zoom(ZoomOptions {
        pkce: false,
        ..zoom_options()
    });

    let url = provider.create_authorization_url(ZoomAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: None,
    })?;

    assert_eq!(query_value(&url, "code_challenge_method"), None);
    assert_eq!(query_value(&url, "code_challenge"), None);
    Ok(())
}

#[test]
fn zoom_authorization_url_requires_code_verifier_when_pkce_is_enabled() {
    let provider = zoom(zoom_options());

    let result = provider.create_authorization_url(ZoomAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: None,
    });

    assert!(matches!(
        result,
        Err(OAuthError::MissingOption("code_verifier"))
    ));
}

#[test]
fn zoom_authorization_code_request_uses_post_client_authentication() -> Result<(), OAuthError> {
    let provider = zoom(zoom_options());

    let request = provider.authorization_code_request(ZoomAuthorizationCodeRequest {
        code: "code-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("verifier-1".to_owned()),
    })?;

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("code_verifier"), Some("verifier-1"));
    assert_eq!(request.form_value("client_id"), Some("zoom-client"));
    assert_eq!(request.form_value("client_secret"), Some("zoom-secret"));
    assert_eq!(request.header("authorization"), None);
    Ok(())
}

#[test]
fn zoom_refresh_access_token_request_uses_zoom_endpoint_and_credentials() -> Result<(), OAuthError>
{
    let provider = zoom(ZoomOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("zoom-client")),
            client_key: Some("zoom-key".to_owned()),
            client_secret: Some("zoom-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..ZoomOptions::default()
    });

    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(provider.token_endpoint(), ZOOM_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), Some("zoom-client"));
    assert_eq!(request.form_value("client_key"), Some("zoom-key"));
    assert_eq!(request.form_value("client_secret"), Some("zoom-secret"));
    Ok(())
}

#[test]
fn zoom_profile_maps_verified_profile_to_oauth_user_info() {
    let mapped = ZoomProvider::map_profile(zoom_profile(1));

    assert_eq!(mapped.user.id, "zoom-user");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(mapped.user.email_verified);
}

#[test]
fn zoom_profile_maps_unverified_profile_to_oauth_user_info() {
    let mapped = ZoomProvider::map_profile(zoom_profile(0));

    assert!(!mapped.user.email_verified);
}

#[tokio::test]
async fn zoom_userinfo_fetches_profile_with_bearer_token() -> Result<(), OAuthError> {
    let server = JsonServer::spawn(
        200,
        json!({
            "id": "zoom-user",
            "display_name": "Ada Lovelace",
            "email": "ada@example.com",
            "pic_url": "https://cdn.example.com/ada.png",
            "verified": 1
        }),
    );
    let provider = ZoomProvider::new_with_user_info_endpoint(zoom_options(), server.url())
        .with_http_client(ProviderHttpClient::permissive());

    let info = provider
        .get_user_info(&tokens("access-1"))
        .await?
        .expect("Zoom profile should map");

    assert_eq!(info.user.id, "zoom-user");
    assert_eq!(
        server.request_header("authorization").as_deref(),
        Some("Bearer access-1")
    );
    Ok(())
}

#[tokio::test]
async fn zoom_userinfo_returns_none_for_http_errors() -> Result<(), OAuthError> {
    let server = JsonServer::spawn(500, json!({ "error": "server_error" }));
    let provider = ZoomProvider::new_with_user_info_endpoint(zoom_options(), server.url())
        .with_http_client(ProviderHttpClient::permissive());

    assert!(provider.get_user_info(&tokens("access-1")).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn zoom_userinfo_rejects_private_literal_ip_endpoint_by_default() -> Result<(), OAuthError> {
    let server = JsonServer::spawn(
        200,
        json!({
            "id": "zoom-user",
            "display_name": "Ada Lovelace",
            "email": "ada@example.com",
            "pic_url": "https://cdn.example.com/ada.png",
            "verified": 1
        }),
    );

    // `server.url()` is a loopback literal IP, refused by the default client.
    let guarded = ZoomProvider::new_with_user_info_endpoint(zoom_options(), server.url());
    assert!(matches!(
        guarded.get_user_info(&tokens("access-1")).await,
        Err(OAuthError::InvalidConfiguration(_))
    ));

    // An explicitly permissive client may still reach the loopback fixture.
    let permissive = ZoomProvider::new_with_user_info_endpoint(zoom_options(), server.url())
        .with_http_client(ProviderHttpClient::permissive());
    let info = permissive
        .get_user_info(&tokens("access-1"))
        .await?
        .expect("permissive client should reach loopback fixture");
    assert_eq!(info.user.id, "zoom-user");
    Ok(())
}

fn zoom_options() -> ZoomOptions {
    ZoomOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("zoom-client")),
            client_secret: Some("zoom-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..ZoomOptions::default()
    }
}

fn zoom_profile(verified: i64) -> ZoomProfile {
    ZoomProfile {
        id: "zoom-user".to_owned(),
        display_name: Some("Ada Lovelace".to_owned()),
        email: Some("ada@example.com".to_owned()),
        pic_url: Some("https://cdn.example.com/ada.png".to_owned()),
        verified,
        ..ZoomProfile::default()
    }
}

fn tokens(access_token: &str) -> OAuth2Tokens {
    OAuth2Tokens {
        access_token: Some(access_token.to_owned()),
        ..OAuth2Tokens::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

struct JsonServer {
    url: String,
    request: Arc<Mutex<String>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl JsonServer {
    fn spawn(status: u16, response: serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("local addr should exist")
        );
        let request = Arc::new(Mutex::new(String::new()));
        let request_for_thread = Arc::clone(&request);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should accept");
            let mut buffer = [0; 8192];
            let read = stream.read(&mut buffer).expect("request should read");
            let request_text = String::from_utf8_lossy(&buffer[..read]).to_string();
            *request_for_thread.lock().expect("request lock") = request_text;
            let response_body = response.to_string();
            let status_text = if status == 200 {
                "200 OK"
            } else {
                "500 Internal Server Error"
            };
            let response = format!(
                "HTTP/1.1 {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        Self {
            url,
            request,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn request_header(&self, key: &str) -> Option<String> {
        let key = key.to_ascii_lowercase();
        self.request
            .lock()
            .expect("request lock")
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case(&key))
            .map(|(_, value)| value.trim().to_owned())
    }
}

impl Drop for JsonServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
