use openauth_core::context::create_auth_context;
use openauth_core::db::{Create, DbAdapter, DbValue};
use openauth_core::options::OpenAuthOptions;
use openauth_sqlx::SqliteAdapter;
use openauth_sso::{
    sso, CreateSsoProviderInput, OidcConfig, SamlConfig, SamlSpMetadata, SecretString, SsoOptions,
    SsoProviderStore,
};
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn sqlite_schema_migration_creates_sso_provider_table_and_columns(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![sso(SsoOptions::default().domain_verification_enabled(true))],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = SqliteAdapter::with_schema(pool.clone(), context.db_schema.clone());

    adapter.create_schema(&context.db_schema, None).await?;

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sso_providers'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(table_count, 1);

    let columns =
        sqlx::query_scalar::<_, String>("SELECT name FROM pragma_table_info('sso_providers')")
            .fetch_all(&pool)
            .await?;
    assert!(columns.iter().any(|column| column == "provider_id"));
    assert!(columns.iter().any(|column| column == "oidc_config"));
    assert!(columns.iter().any(|column| column == "saml_config"));
    assert!(columns.iter().any(|column| column == "domain_verified"));
    assert!(columns
        .iter()
        .all(|column| !column.contains(char::is_uppercase)));

    Ok(())
}

#[tokio::test]
async fn provider_store_sanitizes_oidc_secret() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = openauth_core::db::MemoryAdapter::new();
    let oidc_config = OidcConfig {
        issuer: "https://idp.example.com".to_owned(),
        pkce: true,
        client_id: "client-123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: "https://idp.example.com/.well-known/openid-configuration".to_owned(),
        authorization_endpoint: Some("https://idp.example.com/auth".to_owned()),
        token_endpoint: Some("https://idp.example.com/token".to_owned()),
        user_info_endpoint: None,
        jwks_endpoint: Some("https://idp.example.com/jwks".to_owned()),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
        scopes: Some(vec!["openid".to_owned(), "email".to_owned()]),
        mapping: None,
        override_user_info: false,
    };
    let created = SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: Some(serde_json::to_string(&oidc_config)?),
            saml_config: None,
            domain_verified: Some(false),
        })
        .await?;

    let sanitized = created.sanitized("https://app.example.com");
    let oidc = sanitized
        .oidc_config
        .as_ref()
        .ok_or("missing oidc config")?;

    assert_eq!(oidc.client_id_last_four, "****3456");
    assert!(!serde_json::to_value(&sanitized)?
        .to_string()
        .contains("super-secret"));

    Ok(())
}

#[test]
fn typed_sso_secrets_redact_debug_output() {
    let oidc_config = OidcConfig {
        issuer: "https://idp.example.com".to_owned(),
        pkce: true,
        client_id: "client-123456".to_owned(),
        client_secret: openauth_oidc::SecretString::new("super-secret"),
        discovery_endpoint: "https://idp.example.com/.well-known/openid-configuration".to_owned(),
        authorization_endpoint: Some("https://idp.example.com/auth".to_owned()),
        token_endpoint: Some("https://idp.example.com/token".to_owned()),
        user_info_endpoint: None,
        jwks_endpoint: Some("https://idp.example.com/jwks".to_owned()),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    let saml_config = SamlConfig {
        issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
        entry_point: "https://idp.example.com/saml/sso".to_owned(),
        cert: "CERTIFICATE".to_owned(),
        callback_url: "https://app.example.com/sso/saml2/sp/acs/saml-okta".to_owned(),
        acs_url: None,
        audience: None,
        idp_metadata: None,
        sp_metadata: SamlSpMetadata {
            private_key: Some(SecretString::new("sp-private-key")),
            private_key_pass: Some(SecretString::new("sp-private-key-pass")),
            ..SamlSpMetadata::default()
        },
        mapping: None,
        want_assertions_signed: true,
        authn_requests_signed: true,
        signature_algorithm: None,
        digest_algorithm: None,
        identifier_format: None,
        private_key: Some(SecretString::new("top-private-key")),
        decryption_pvk: Some(SecretString::new("decryption-private-key")),
        additional_params: None,
    };

    let debug = format!("{oidc_config:?} {saml_config:?}");

    assert!(debug.contains("client_secret: SecretString(REDACTED)"));
    assert!(debug.contains("private_key: Some(SecretString(REDACTED))"));
    assert!(!debug.contains("super-secret"));
    assert!(!debug.contains("sp-private-key"));
    assert!(!debug.contains("top-private-key"));
    assert!(!debug.contains("decryption-private-key"));
}

#[tokio::test]
async fn provider_store_masks_short_oidc_client_id() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = openauth_core::db::MemoryAdapter::new();
    let oidc_config = OidcConfig {
        issuer: "https://idp.example.com".to_owned(),
        pkce: true,
        client_id: "abc".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: "https://idp.example.com/.well-known/openid-configuration".to_owned(),
        authorization_endpoint: Some("https://idp.example.com/auth".to_owned()),
        token_endpoint: Some("https://idp.example.com/token".to_owned()),
        user_info_endpoint: None,
        jwks_endpoint: Some("https://idp.example.com/jwks".to_owned()),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    let created = SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: Some(serde_json::to_string(&oidc_config)?),
            saml_config: None,
            domain_verified: Some(false),
        })
        .await?;

    let sanitized = created.sanitized("https://app.example.com");
    let oidc = sanitized
        .oidc_config
        .as_ref()
        .ok_or("missing oidc config")?;

    assert_eq!(oidc.client_id_last_four, "****");

    Ok(())
}

#[tokio::test]
async fn provider_store_accepts_json_config_values_from_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = openauth_core::db::MemoryAdapter::new();
    adapter
        .create(
            Create::new("sso_provider")
                .data("id", DbValue::String("provider_1".to_owned()))
                .data("issuer", DbValue::String("https://idp.example.com".to_owned()))
                .data("provider_id", DbValue::String("okta".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data("organization_id", DbValue::Null)
                .data("domain", DbValue::String("example.com".to_owned()))
                .data("domain_verified", DbValue::Boolean(false))
                .data("created_at", DbValue::Timestamp(time::OffsetDateTime::now_utc()))
                .data(
                    "oidc_config",
                    DbValue::Json(serde_json::json!({
                        "issuer": "https://idp.example.com",
                        "pkce": true,
                        "clientId": "client-123456",
                        "clientSecret": "super-secret",
                        "discoveryEndpoint": "https://idp.example.com/.well-known/openid-configuration",
                        "authorizationEndpoint": "https://idp.example.com/auth",
                        "tokenEndpoint": "https://idp.example.com/token",
                        "userInfoEndpoint": null,
                        "jwksEndpoint": "https://idp.example.com/jwks",
                        "overrideUserInfo": false
                    })),
                )
                .data("saml_config", DbValue::Null)
                .force_allow_id(),
        )
        .await?;

    let provider = SsoProviderStore::new(&adapter)
        .find_by_provider_id("okta")
        .await?
        .ok_or("missing provider")?;
    let sanitized = provider.sanitized("https://app.example.com");
    let oidc = sanitized
        .oidc_config
        .as_ref()
        .ok_or("missing oidc config")?;

    assert_eq!(oidc.client_id_last_four, "****3456");
    assert!(!serde_json::to_value(&sanitized)?
        .to_string()
        .contains("super-secret"));

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn provider_store_returns_saml_certificate_metadata_without_raw_cert(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = openauth_core::db::MemoryAdapter::new();
    let saml_config = serde_json::json!({
        "issuer": "https://app.example.com/sso/saml2/sp/metadata",
        "entryPoint": "https://idp.example.com/saml/sso",
        "cert": TEST_CERTIFICATE,
        "callbackUrl": "https://app.example.com/post-auth-callback",
        "acsUrl": "https://app.example.com/sso/saml2/sp/acs/saml-okta",
        "spMetadata": {},
        "wantAssertionsSigned": true,
        "authnRequestsSigned": false
    });
    let created = SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "saml-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: Some(serde_json::to_string(&saml_config)?),
            domain_verified: Some(false),
        })
        .await?;

    let sanitized = created.sanitized("https://app.example.com");
    let saml = sanitized
        .saml_config
        .as_ref()
        .ok_or("missing saml config")?;

    assert_eq!(
        saml.certificate_sha256_fingerprint,
        "067da7eb62ba6c3eb3d531ea94e2ad580bd4a20fbf04ef56abc0f32de5149c91"
    );
    assert_eq!(
        saml.certificate_not_before.as_deref(),
        Some("2026-05-18T04:49:57Z")
    );
    assert_eq!(
        saml.certificate_not_after.as_deref(),
        Some("2036-05-15T04:49:57Z")
    );
    assert_eq!(
        saml.certificate_public_key_algorithm.as_deref(),
        Some("RSA-2048")
    );
    assert_eq!(
        saml.acs_url.as_deref(),
        Some("https://app.example.com/sso/saml2/sp/acs/saml-okta")
    );
    assert!(!serde_json::to_value(&sanitized)?
        .to_string()
        .contains(TEST_CERTIFICATE));

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn provider_store_returns_saml_certificate_parse_error_without_raw_cert(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = openauth_core::db::MemoryAdapter::new();
    let saml_config = serde_json::json!({
        "issuer": "https://app.example.com/sso/saml2/sp/metadata",
        "entryPoint": "https://idp.example.com/saml/sso",
        "cert": "not-a-certificate",
        "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/saml-okta",
        "spMetadata": {},
        "wantAssertionsSigned": true,
        "authnRequestsSigned": false
    });
    let created = SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "saml-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: Some(serde_json::to_string(&saml_config)?),
            domain_verified: Some(false),
        })
        .await?;

    let sanitized = created.sanitized("https://app.example.com");
    let saml = sanitized
        .saml_config
        .as_ref()
        .ok_or("missing saml config")?;
    let serialized = serde_json::to_value(&sanitized)?;

    assert_eq!(
        saml.certificate_error.as_deref(),
        Some("Failed to parse certificate")
    );
    assert!(saml.certificate_sha256_fingerprint.is_empty());
    assert!(!serialized.to_string().contains("not-a-certificate"));

    Ok(())
}

#[cfg(feature = "saml")]
const TEST_CERTIFICATE: &str = "\
MIIDFTCCAf2gAwIBAgIUYqceCSeUr0EzhKEqp7KdKUivL+IwDQYJKoZIhvcNAQEL\
BQAwGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMB4XDTI2MDUxODA0NDk1N1oX\
DTM2MDUxNTA0NDk1N1owGjEYMBYGA1UEAwwPaWRwLmV4YW1wbGUuY29tMIIBIjAN\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluDjDG8JloZCKQnRAbERGsqub+W1\
VyJ1nGiN1YLtCy0bvYLTtdwH6aaO+ji9ggedqFeqUYhOzEEP+UyCwC1tHYgdMi83\
6MjbKIADQAhHkQ5SCQH0IAlcrSN8gvSPXXk4riltBeqeHzLTwCT1yoG+Go5DDb4v\
s0z5FuffboJFUYtXC/l1vLbKAQ6eIRnlsxmvHLXjSA/UGnhfVNZm3NFlnKByWcuZ\
asnAur9chFlrhJPoez99V18VElUI/gsbBxI1Nm2i18JgN1yVDVd52C3XLvMid7Cm\
xHBdj4VH+/GkjC+X3OyOUMKDetIv0J5dJOaxELio7EFrW9J0CZ8MqwfjKwIDAQAB\
o1MwUTAdBgNVHQ4EFgQUixOG/MiMH4Pah1OIGjoVLr4bP7YwHwYDVR0jBBgwFoAU\
ixOG/MiMH4Pah1OIGjoVLr4bP7YwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\
AQsFAAOCAQEALvwY4HNYNXdC4+Hwb2LLhQS1/zU16MqOuAU2r+pFFEO3eSSw1Yyh\
4a7Q1risZObsGZOyyJiywGsM7T77BUg1XGoC8+4TA+/T98XehSq4eOSYFjUjcXuH\
QifAQRs03K8UvWDxrH9TMKPZD8yww7jjcw9CCUtiDjYxLgEenknSEfWTtjgfuDpt\
mQvRp6eLV6VgaoKKqKJ3gbXlEM2f08P69/VwsA+o3XnzovdbFURxacGpmfDLWvoc\
0ouXkCRpylhdPRDTAP9abEQQ3ocfoZavA+HHM3f7vXXY7UzVP0xjOsd4Rcyt1LVv\
a+AQVq62bFC4juYYMXSRWevywclZfqY7LQ==";
