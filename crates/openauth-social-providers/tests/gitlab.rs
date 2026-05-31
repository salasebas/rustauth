#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::gitlab::{
    gitlab, GitlabAuthorizationUrlRequest, GitlabOptions, GitlabProfile,
    GITLAB_AUTHORIZATION_ENDPOINT, GITLAB_ID, GITLAB_NAME, GITLAB_TOKEN_ENDPOINT,
};
use openauth_social_providers::http::ProviderHttpClient;
use serde_json::json;

#[test]
fn gitlab_provider_exposes_upstream_metadata() {
    let provider = gitlab(gitlab_options());

    assert_eq!((provider.id(), provider.name()), (GITLAB_ID, GITLAB_NAME));
}

#[test]
fn gitlab_authorization_url_uses_default_endpoint_and_scope() -> Result<(), OAuthError> {
    let provider = gitlab(gitlab_options());

    let url = provider.create_authorization_url(GitlabAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["api".to_owned()],
        login_hint: Some("ada@example.com".to_owned()),
    })?;

    assert!(url.as_str().starts_with(GITLAB_AUTHORIZATION_ENDPOINT));
    assert_eq!(query_value(&url, "scope"), Some("read_user api".to_owned()));
    assert_eq!(
        query_value(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("gitlab-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    Ok(())
}

#[test]
fn gitlab_custom_issuer_derives_and_cleans_endpoints() {
    let provider = gitlab(GitlabOptions {
        issuer: Some("https://gitlab.example.com///".to_owned()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    });

    assert_eq!(
        provider.authorization_endpoint(),
        "https://gitlab.example.com/oauth/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://gitlab.example.com/oauth/token"
    );
    assert_eq!(
        provider.userinfo_endpoint(),
        "https://gitlab.example.com/api/v4/user"
    );
}

#[test]
fn gitlab_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let provider = gitlab(GitlabOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("gitlab-client")),
            disable_default_scope: true,
            scope: vec!["read_api".to_owned()],
            ..ProviderOptions::default()
        },
        ..GitlabOptions::default()
    });

    let url = provider.create_authorization_url(GitlabAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["api".to_owned()],
        ..GitlabAuthorizationUrlRequest::default()
    })?;

    assert_eq!(query_value(&url, "scope"), Some("read_api api".to_owned()));
    Ok(())
}

#[test]
fn gitlab_token_requests_use_existing_oauth_form_behavior() -> Result<(), OAuthError> {
    let provider = gitlab(gitlab_options());

    let code_request = provider.authorization_code_request(
        "code-1",
        Some("verifier-1"),
        "https://app.example.com/auth/callback",
    )?;
    assert_eq!(
        code_request.form_value("grant_type"),
        Some("authorization_code")
    );
    assert_eq!(code_request.form_value("client_id"), Some("gitlab-client"));
    assert_eq!(
        code_request.form_value("client_secret"),
        Some("gitlab-secret")
    );
    assert_eq!(code_request.form_value("code_verifier"), Some("verifier-1"));

    let refresh_request = provider.refresh_access_token_request("refresh-1")?;
    assert_eq!(provider.token_endpoint(), GITLAB_TOKEN_ENDPOINT);
    assert_eq!(
        refresh_request.form_value("grant_type"),
        Some("refresh_token")
    );
    assert_eq!(
        refresh_request.form_value("refresh_token"),
        Some("refresh-1")
    );
    assert_eq!(
        refresh_request.form_value("client_id"),
        Some("gitlab-client")
    );
    Ok(())
}

#[test]
fn gitlab_profile_maps_email_verified_to_false_by_default() {
    let profile = GitlabProfile {
        id: 123,
        username: Some("ada".to_owned()),
        name: Some("Ada Lovelace".to_owned()),
        email: Some("ada@example.com".to_owned()),
        avatar_url: Some("https://cdn.example.com/ada.png".to_owned()),
        email_verified: None,
        ..GitlabProfile::default()
    };

    let user = profile.to_user_info();

    assert_eq!(user.id, "123");
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(!user.email_verified);
}

#[tokio::test]
async fn gitlab_userinfo_accepts_active_unlocked_profiles() -> Result<(), OAuthError> {
    let server = JsonServer::spawn(
        200,
        json!({
            "id": 123,
            "username": "ada",
            "email": "ada@example.com",
            "name": "Ada Lovelace",
            "state": "active",
            "avatar_url": "https://cdn.example.com/ada.png",
            "email_verified": true
        }),
    );
    let provider = gitlab(GitlabOptions {
        issuer: Some(server.url()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    })
    .with_http_client(ProviderHttpClient::permissive());

    let info = provider
        .get_user_info(&tokens("access-1"))
        .await?
        .expect("active unlocked GitLab profile should map");

    assert_eq!(info.user.id, "123");
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        server.request_header("authorization").as_deref(),
        Some("Bearer access-1")
    );
    Ok(())
}

#[tokio::test]
async fn gitlab_userinfo_rejects_inactive_locked_and_http_errors() -> Result<(), OAuthError> {
    let inactive = JsonServer::spawn(
        200,
        json!({
            "id": 123,
            "username": "ada",
            "email": "ada@example.com",
            "name": "Ada Lovelace",
            "state": "blocked",
            "avatar_url": null
        }),
    );
    let inactive_provider = gitlab(GitlabOptions {
        issuer: Some(inactive.url()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    })
    .with_http_client(ProviderHttpClient::permissive());
    assert!(inactive_provider
        .get_user_info(&tokens("access-1"))
        .await?
        .is_none());

    let locked = JsonServer::spawn(
        200,
        json!({
            "id": 123,
            "username": "ada",
            "email": "ada@example.com",
            "name": "Ada Lovelace",
            "state": "active",
            "locked": true,
            "avatar_url": null
        }),
    );
    let locked_provider = gitlab(GitlabOptions {
        issuer: Some(locked.url()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    })
    .with_http_client(ProviderHttpClient::permissive());
    assert!(locked_provider
        .get_user_info(&tokens("access-1"))
        .await?
        .is_none());

    let http_error = JsonServer::spawn(500, json!({ "error": "server_error" }));
    let http_error_provider = gitlab(GitlabOptions {
        issuer: Some(http_error.url()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    })
    .with_http_client(ProviderHttpClient::permissive());
    assert!(http_error_provider
        .get_user_info(&tokens("access-1"))
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn gitlab_userinfo_rejects_private_literal_ip_issuer_by_default() -> Result<(), OAuthError> {
    let server = JsonServer::spawn(
        200,
        json!({
            "id": 7,
            "username": "ada",
            "email": "ada@example.com",
            "name": "Ada Lovelace",
            "state": "active",
            "email_verified": true
        }),
    );

    // `server.url()` is a loopback literal IP (127.0.0.1:port). The default
    // SSRF-guarded client must refuse it before connecting.
    let guarded = gitlab(GitlabOptions {
        issuer: Some(server.url()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    });
    assert!(matches!(
        guarded.get_user_info(&tokens("access-1")).await,
        Err(OAuthError::InvalidConfiguration(_))
    ));

    // An explicitly permissive client may still reach the loopback fixture.
    let permissive = gitlab(GitlabOptions {
        issuer: Some(server.url()),
        ..GitlabOptions {
            oauth: gitlab_provider_options(),
            ..GitlabOptions::default()
        }
    })
    .with_http_client(ProviderHttpClient::permissive());
    let info = permissive
        .get_user_info(&tokens("access-1"))
        .await?
        .expect("permissive client should reach loopback fixture");
    assert_eq!(info.user.id, "7");
    Ok(())
}

fn gitlab_options() -> GitlabOptions {
    GitlabOptions {
        oauth: gitlab_provider_options(),
        ..GitlabOptions::default()
    }
}

fn gitlab_provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("gitlab-client")),
        client_secret: Some("gitlab-secret".to_owned()),
        ..ProviderOptions::default()
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
