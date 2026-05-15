use super::common::*;

#[test]
fn helper_providers_match_upstream_defaults() {
    assert_eq!(
        auth0(Auth0Options {
            base: helper_base("client", "secret"),
            domain: "https://tenant.auth0.com".to_owned(),
        })
        .discovery_url,
        Some("https://tenant.auth0.com/.well-known/openid-configuration".to_owned())
    );
    assert_eq!(
        okta(OktaOptions {
            base: helper_base("client", "secret"),
            issuer: "https://dev.okta.com/oauth2/default/".to_owned(),
        })
        .discovery_url,
        Some("https://dev.okta.com/oauth2/default/.well-known/openid-configuration".to_owned())
    );
    assert_eq!(
        keycloak(KeycloakOptions {
            base: helper_base("client", "secret"),
            issuer: "https://kc.example.com/realms/acme/".to_owned(),
        })
        .discovery_url,
        Some("https://kc.example.com/realms/acme/.well-known/openid-configuration".to_owned())
    );
    assert_eq!(
        gumroad(GumroadOptions {
            base: helper_base("client", "secret"),
        })
        .provider_id,
        "gumroad"
    );
    assert_eq!(
        hubspot(HubSpotOptions {
            base: helper_base("client", "secret"),
        })
        .scopes,
        vec!["oauth"]
    );
    assert_eq!(
        line(LineOptions {
            base: helper_base("client", "secret"),
            provider_id: Some("line-jp".to_owned()),
        })
        .provider_id,
        "line-jp"
    );
    assert_eq!(
        microsoft_entra_id(MicrosoftEntraIdOptions {
            base: helper_base("client", "secret"),
            tenant_id: "common".to_owned(),
        })
        .authorization_url,
        Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_owned())
    );
    assert_eq!(
        patreon(PatreonOptions {
            base: helper_base("client", "secret"),
        })
        .scopes,
        vec!["identity[email]"]
    );
    assert_eq!(
        slack(SlackOptions {
            base: helper_base("client", "secret"),
        })
        .provider_id,
        "slack"
    );
}

#[test]
fn helper_provider_options_apply_overrides() {
    let config = slack(SlackOptions {
        base: BaseOAuthProviderOptions {
            client_id: "client".to_owned(),
            client_secret: Some("secret".to_owned()),
            scopes: Some(vec!["openid".to_owned(), "team".to_owned()]),
            redirect_uri: Some("https://app.example.com/custom/callback".to_owned()),
            pkce: true,
            disable_implicit_sign_up: true,
            disable_sign_up: true,
            override_user_info: true,
        },
    });

    assert_eq!(config.scopes, vec!["openid", "team"]);
    assert_eq!(
        config.redirect_uri.as_deref(),
        Some("https://app.example.com/custom/callback")
    );
    assert!(config.pkce);
    assert!(config.disable_implicit_sign_up);
    assert!(config.disable_sign_up);
    assert!(config.override_user_info);
}
