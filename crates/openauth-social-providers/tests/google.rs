use openauth_oauth::oauth2::{ClientId, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::google::{
    GoogleAccessType, GoogleAuthorizationUrlRequest, GoogleDisplay, GoogleOptions, GoogleProfile,
    GoogleProvider,
};

#[test]
fn google_provider_exposes_upstream_metadata() {
    let provider = GoogleProvider::new(GoogleOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("google-client")),
            client_secret: Some("google-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..GoogleOptions::default()
    });

    assert_eq!(provider.id(), "google");
    assert_eq!(provider.name(), "Google");
}

#[test]
fn authorization_url_includes_google_defaults_and_options() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = GoogleProvider::new(GoogleOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::Multiple(vec![
                "web-client".to_owned(),
                "ios-client".to_owned(),
            ])),
            client_secret: Some("google-secret".to_owned()),
            redirect_uri: Some("https://auth.example.com/google/callback".to_owned()),
            scope: vec!["calendar.readonly".to_owned()],
            prompt: Some("select_account consent".to_owned()),
            ..ProviderOptions::default()
        },
        access_type: Some(GoogleAccessType::Offline),
        display: Some(GoogleDisplay::Popup),
        hd: Some("example.com".to_owned()),
    });

    let url = provider.create_authorization_url(GoogleAuthorizationUrlRequest {
        state: "state-123".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["drive.metadata.readonly".to_owned()],
        login_hint: Some("ada@example.com".to_owned()),
        display: Some(GoogleDisplay::Touch),
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://accounts.google.com/o/oauth2/v2/auth")
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("web-client".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("email profile openid calendar.readonly drive.metadata.readonly".to_owned())
    );
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/google/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "prompt"),
        Some("select_account consent".to_owned())
    );
    assert_eq!(query_value(&url, "access_type"), Some("offline".to_owned()));
    assert_eq!(query_value(&url, "display"), Some("touch".to_owned()));
    assert_eq!(
        query_value(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
    assert_eq!(query_value(&url, "hd"), Some("example.com".to_owned()));
    assert_eq!(
        query_value(&url, "include_granted_scopes"),
        Some("true".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
    Ok(())
}

#[test]
fn authorization_url_can_disable_default_scope() -> Result<(), Box<dyn std::error::Error>> {
    let provider = GoogleProvider::new(GoogleOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("google-client")),
            client_secret: Some("google-secret".to_owned()),
            disable_default_scope: true,
            scope: vec!["calendar.readonly".to_owned()],
            ..ProviderOptions::default()
        },
        access_type: Some(GoogleAccessType::Online),
        display: Some(GoogleDisplay::Wap),
        ..GoogleOptions::default()
    });

    let url = provider.create_authorization_url(GoogleAuthorizationUrlRequest {
        state: "state".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["drive.metadata.readonly".to_owned()],
        ..GoogleAuthorizationUrlRequest::default()
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("calendar.readonly drive.metadata.readonly".to_owned())
    );
    assert_eq!(query_value(&url, "access_type"), Some("online".to_owned()));
    assert_eq!(query_value(&url, "display"), Some("wap".to_owned()));
    Ok(())
}

#[test]
fn authorization_url_requires_client_id_secret_and_code_verifier() {
    let missing_client_id = GoogleProvider::new(GoogleOptions {
        oauth: ProviderOptions {
            client_secret: Some("google-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..GoogleOptions::default()
    });
    assert!(missing_client_id
        .create_authorization_url(valid_authorization_request())
        .is_err());

    let missing_secret = GoogleProvider::new(GoogleOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("google-client")),
            ..ProviderOptions::default()
        },
        ..GoogleOptions::default()
    });
    assert!(missing_secret
        .create_authorization_url(valid_authorization_request())
        .is_err());

    let missing_verifier = GoogleProvider::new(valid_options());
    assert!(missing_verifier
        .create_authorization_url(GoogleAuthorizationUrlRequest {
            code_verifier: None,
            ..valid_authorization_request()
        })
        .is_err());
}

#[test]
fn google_profile_maps_to_oauth_user_info() {
    let profile = GoogleProfile {
        aud: "google-client".to_owned(),
        azp: "google-client".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        exp: 4_102_444_800,
        family_name: "Lovelace".to_owned(),
        given_name: "Ada".to_owned(),
        hd: Some("example.com".to_owned()),
        iat: 1_704_067_200,
        iss: "https://accounts.google.com".to_owned(),
        jti: Some("token-id".to_owned()),
        locale: Some("en".to_owned()),
        name: "Ada Lovelace".to_owned(),
        nbf: None,
        picture: "https://photos.example.com/ada.jpg".to_owned(),
        sub: "google-subject".to_owned(),
        nonce: Some("nonce".to_owned()),
        extra: Default::default(),
    };

    let user = GoogleProvider::map_profile_to_user_info(&profile);

    assert_eq!(user.id, "google-subject");
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert!(user.email_verified);
    assert_eq!(
        user.image.as_deref(),
        Some("https://photos.example.com/ada.jpg")
    );
}

fn valid_options() -> GoogleOptions {
    GoogleOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("google-client")),
            client_secret: Some("google-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..GoogleOptions::default()
    }
}

fn valid_authorization_request() -> GoogleAuthorizationUrlRequest {
    GoogleAuthorizationUrlRequest {
        state: "state".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        ..GoogleAuthorizationUrlRequest::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
