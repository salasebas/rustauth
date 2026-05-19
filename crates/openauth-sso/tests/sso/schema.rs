use openauth_core::context::create_auth_context;
use openauth_core::db::DbFieldType;
use openauth_core::options::OpenAuthOptions;
use openauth_sso::{sso, SsoOptions, UPSTREAM_PLUGIN_ID, VERSION};

#[test]
fn sso_public_constants_match_plugin_metadata() {
    let plugin = sso(SsoOptions::default());

    assert_eq!(UPSTREAM_PLUGIN_ID, "sso");
    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.version.as_deref(), Some(VERSION));
}

#[test]
fn sso_plugin_registers_snake_case_plural_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![sso(SsoOptions::default())],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("ssoProvider")
        .ok_or("missing ssoProvider table")?;
    assert_eq!(table.name, "sso_providers");

    let provider_id = context.db_schema.field("ssoProvider", "providerId")?;
    assert_eq!(provider_id.name, "provider_id");
    assert_eq!(provider_id.field_type, DbFieldType::String);
    assert!(provider_id.required);
    assert!(provider_id.unique);

    let user_id = context.db_schema.field("ssoProvider", "userId")?;
    assert_eq!(user_id.name, "user_id");
    assert!(user_id.foreign_key.is_some());

    let oidc_config = context.db_schema.field("ssoProvider", "oidcConfig")?;
    assert_eq!(oidc_config.name, "oidc_config");
    assert_eq!(oidc_config.field_type, DbFieldType::String);
    assert!(!oidc_config.required);
    assert!(!oidc_config.returned);

    let saml_config = context.db_schema.field("ssoProvider", "samlConfig")?;
    assert_eq!(saml_config.name, "saml_config");
    assert_eq!(saml_config.field_type, DbFieldType::String);
    assert!(!saml_config.required);
    assert!(!saml_config.returned);

    assert!(context
        .db_schema
        .field("ssoProvider", "domainVerified")
        .is_err());

    Ok(())
}

#[test]
fn domain_verification_adds_domain_verified_field() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![sso(SsoOptions::default().domain_verification_enabled(true))],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let field = context.db_schema.field("ssoProvider", "domainVerified")?;

    assert_eq!(field.name, "domain_verified");
    assert_eq!(field.field_type, DbFieldType::Boolean);
    assert!(!field.required);

    Ok(())
}

#[test]
fn sso_plugin_registers_expected_endpoint_surface() {
    let plugin = sso(SsoOptions::default().domain_verification_enabled(true));
    let endpoints = plugin
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.method.clone(), endpoint.path.as_str()))
        .collect::<Vec<_>>();

    assert!(endpoints.contains(&(http::Method::GET, "/sso/saml2/sp/metadata")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/register")));
    assert!(endpoints.contains(&(http::Method::POST, "/sign-in/sso")));
    assert!(endpoints.contains(&(http::Method::GET, "/sso/callback/:providerId")));
    assert!(endpoints.contains(&(http::Method::GET, "/sso/callback")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/callback/:providerId")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/sp/acs/:providerId")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/sp/slo/:providerId")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/logout/:providerId")));
    assert!(endpoints.contains(&(http::Method::GET, "/sso/providers")));
    assert!(endpoints.contains(&(http::Method::GET, "/sso/get-provider")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/update-provider")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/delete-provider")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/request-domain-verification")));
    assert!(endpoints.contains(&(http::Method::POST, "/sso/verify-domain")));
}

#[test]
fn sso_plugin_registers_rate_limit_rules_for_expensive_entrypoints() {
    let plugin = sso(SsoOptions::default().domain_verification_enabled(true));
    let rules = plugin
        .rate_limit
        .iter()
        .map(|rule| (rule.path.as_str(), rule.rule.window, rule.rule.max))
        .collect::<Vec<_>>();

    assert!(rules.contains(&("/sso/register", 60, 10)));
    assert!(rules.contains(&("/sso/request-domain-verification", 60, 5)));
    assert!(rules.contains(&("/sso/verify-domain", 60, 5)));
    assert!(rules.contains(&("/sso/callback", 60, 30)));
    assert!(rules.contains(&("/sso/callback/:providerId", 60, 30)));
    assert!(rules.contains(&("/sso/saml2/sp/acs/:providerId", 60, 30)));
    assert!(rules.contains(&("/sso/saml2/callback/:providerId", 60, 30)));
}

#[test]
fn sso_plugin_can_disable_rate_limit_rule_contributions() {
    let plugin = sso(SsoOptions::default().rate_limit_enabled(false));

    assert!(plugin.rate_limit.is_empty());
}
