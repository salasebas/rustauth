use rustauth_core::context::create_auth_context;
use rustauth_core::db::DbFieldType;
use rustauth_core::options::RustAuthOptions;
use rustauth_sso::{sso, SsoOptions, UPSTREAM_PLUGIN_ID, VERSION};
use time::Duration;

#[test]
fn sso_public_constants_match_plugin_metadata() {
    let plugin = sso(SsoOptions::default());

    assert_eq!(UPSTREAM_PLUGIN_ID, "sso");
    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.version.as_deref(), Some(VERSION));
}

#[test]
fn sso_plugin_registers_snake_case_plural_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![sso(SsoOptions::default())],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;

    let table = context
        .db_schema
        .table("sso_provider")
        .ok_or("missing sso_provider table")?;
    assert_eq!(table.name, "sso_providers");

    let provider_id = context.db_schema.field("sso_provider", "provider_id")?;
    assert_eq!(provider_id.name, "provider_id");
    assert_eq!(provider_id.field_type, DbFieldType::String);
    assert!(provider_id.required);
    assert!(provider_id.unique);

    let user_id = context.db_schema.field("sso_provider", "user_id")?;
    assert_eq!(user_id.name, "user_id");
    assert!(user_id.foreign_key.is_some());

    let oidc_config = context.db_schema.field("sso_provider", "oidc_config")?;
    assert_eq!(oidc_config.name, "oidc_config");
    assert_eq!(oidc_config.field_type, DbFieldType::String);
    assert!(!oidc_config.required);
    assert!(!oidc_config.returned);

    let saml_config = context.db_schema.field("sso_provider", "saml_config")?;
    assert_eq!(saml_config.name, "saml_config");
    assert_eq!(saml_config.field_type, DbFieldType::String);
    assert!(!saml_config.required);
    assert!(!saml_config.returned);

    assert!(context
        .db_schema
        .field("sso_provider", "domain_verified")
        .is_err());

    Ok(())
}

#[test]
fn domain_verification_adds_domain_verified_field() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![sso(SsoOptions::default().domain_verification_enabled(true))],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;

    let field = context.db_schema.field("sso_provider", "domain_verified")?;

    assert_eq!(field.name, "domain_verified");
    assert_eq!(field.field_type, DbFieldType::Boolean);
    assert!(!field.required);

    Ok(())
}

#[test]
fn sso_plugin_uses_custom_model_name_for_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![sso(SsoOptions {
            model_name: "enterpriseSsoProvider".to_owned(),
            ..SsoOptions::default()
        })],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;

    assert!(context.db_schema.table("sso_provider").is_none());
    let table = context
        .db_schema
        .table("enterpriseSsoProvider")
        .ok_or("missing custom SSO provider table")?;
    assert_eq!(table.name, "sso_providers");
    assert_eq!(
        context
            .db_schema
            .field("enterpriseSsoProvider", "provider_id")?
            .name,
        "provider_id"
    );

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

    assert!(endpoints.contains(&(http::Method::POST, "/sso/register")));
    assert!(endpoints.contains(&(http::Method::POST, "/sign-in/sso")));
    #[cfg(feature = "oidc")]
    {
        assert!(endpoints.contains(&(http::Method::GET, "/sso/callback/:providerId")));
        assert!(endpoints.contains(&(http::Method::GET, "/sso/callback")));
    }
    #[cfg(feature = "saml")]
    {
        assert!(endpoints.contains(&(http::Method::GET, "/sso/saml2/sp/metadata")));
        assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/callback/:providerId")));
        assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/sp/acs/:providerId")));
        assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/sp/slo/:providerId")));
        assert!(endpoints.contains(&(http::Method::POST, "/sso/saml2/logout/:providerId")));
    }
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

    assert!(rules.contains(&("/sso/register", Duration::seconds(60), 10)));
    assert!(rules.contains(&("/sso/request-domain-verification", Duration::seconds(60), 5)));
    assert!(rules.contains(&("/sso/verify-domain", Duration::seconds(60), 5)));
    #[cfg(feature = "oidc")]
    {
        assert!(rules.contains(&("/sso/callback", Duration::seconds(60), 30)));
        assert!(rules.contains(&("/sso/callback/:providerId", Duration::seconds(60), 30)));
    }
    #[cfg(feature = "saml")]
    {
        assert!(rules.contains(&("/sso/saml2/sp/acs/:providerId", Duration::seconds(60), 30)));
        assert!(rules.contains(&("/sso/saml2/callback/:providerId", Duration::seconds(60), 30)));
    }
}

#[test]
fn sso_plugin_can_disable_rate_limit_rule_contributions() {
    let plugin = sso(SsoOptions::default().rate_limit_enabled(false));

    assert!(plugin.rate_limit.is_empty());
}
