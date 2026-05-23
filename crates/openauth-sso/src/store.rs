use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, FindOne, Update, Where,
};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[cfg(feature = "oidc")]
use crate::oidc_impl::flow::oidc_redirect_uri;
use crate::options::{OidcConfig, SamlConfig};
use crate::schema::SSO_PROVIDER_MODEL;
#[cfg(feature = "saml")]
use crate::utils::certificate_metadata;
use crate::utils::client_id_last_four;

const SSO_PROVIDER_FIELDS: [&str; 9] = [
    "id",
    "issuer",
    "oidcConfig",
    "samlConfig",
    "userId",
    "providerId",
    "organizationId",
    "domain",
    "createdAt",
];

const SSO_PROVIDER_FIELDS_WITH_DOMAIN_VERIFIED: [&str; 10] = [
    "id",
    "issuer",
    "oidcConfig",
    "samlConfig",
    "userId",
    "providerId",
    "organizationId",
    "domain",
    "domainVerified",
    "createdAt",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Raw SSO provider record loaded from the adapter.
pub struct SsoProviderRecord {
    /// Database id.
    pub id: String,
    /// Provider issuer.
    pub issuer: String,
    /// Serialized OIDC config JSON.
    pub oidc_config: Option<String>,
    /// Serialized SAML config JSON.
    pub saml_config: Option<String>,
    /// Owner user id.
    pub user_id: String,
    /// Stable provider id.
    pub provider_id: String,
    /// Optional organization id assigned to provider users.
    pub organization_id: Option<String>,
    /// Comma-separated provider domains.
    pub domain: String,
    /// Domain verification state.
    pub domain_verified: Option<bool>,
    /// Creation timestamp.
    pub created_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
/// Provider representation returned by public read endpoints.
pub struct SanitizedSsoProvider {
    /// Stable provider id.
    pub provider_id: String,
    /// Preferred provider protocol label.
    pub provider_type: String,
    #[serde(rename = "type")]
    /// Upstream-compatible provider protocol label.
    pub upstream_type: String,
    /// Provider issuer.
    pub issuer: String,
    /// Provider domains.
    pub domain: String,
    /// Optional organization id.
    pub organization_id: Option<String>,
    /// Whether the provider domain has been verified.
    pub domain_verified: bool,
    /// Sanitized OIDC config, if configured.
    pub oidc_config: Option<SanitizedOidcConfig>,
    /// Sanitized SAML config, if configured.
    pub saml_config: Option<SanitizedSamlConfig>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "redirectURI")]
    /// Shared OIDC redirect URI shown to clients.
    pub redirect_uri: Option<String>,
    /// SAML service provider metadata URL.
    pub sp_metadata_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
/// OIDC provider config with secret material removed.
pub struct SanitizedOidcConfig {
    /// Discovery endpoint URL.
    pub discovery_endpoint: String,
    /// Last four characters of the client id.
    pub client_id_last_four: String,
    /// Whether PKCE is enabled.
    pub pkce: bool,
    /// Authorization endpoint URL.
    pub authorization_endpoint: Option<String>,
    /// Token endpoint URL.
    pub token_endpoint: Option<String>,
    /// UserInfo endpoint URL.
    pub user_info_endpoint: Option<String>,
    /// JWKS endpoint URL.
    pub jwks_endpoint: Option<String>,
    /// OAuth token revocation endpoint URL.
    pub revocation_endpoint: Option<String>,
    /// OIDC end-session endpoint URL.
    pub end_session_endpoint: Option<String>,
    /// OAuth token introspection endpoint URL.
    pub introspection_endpoint: Option<String>,
    /// Client authentication method selected for the token endpoint.
    pub token_endpoint_authentication: Option<crate::options::TokenEndpointAuthentication>,
    /// Configured default scopes.
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
/// SAML provider config with private key material removed.
pub struct SanitizedSamlConfig {
    /// IdP entry point.
    pub entry_point: String,
    /// Callback URL.
    pub callback_url: String,
    /// Assertion consumer service URL.
    pub acs_url: Option<String>,
    /// Expected audience.
    pub audience: Option<String>,
    /// Whether assertion signatures are required.
    pub want_assertions_signed: bool,
    /// Whether outbound AuthnRequests are signed.
    pub authn_requests_signed: bool,
    /// Requested NameID format.
    pub identifier_format: Option<String>,
    /// Signature algorithm.
    pub signature_algorithm: Option<String>,
    /// Digest algorithm.
    pub digest_algorithm: Option<String>,
    /// SHA-256 fingerprint of the IdP certificate.
    pub certificate_sha256_fingerprint: String,
    /// Certificate validity start, when parseable.
    pub certificate_not_before: Option<String>,
    /// Certificate validity end, when parseable.
    pub certificate_not_after: Option<String>,
    /// Certificate public key algorithm, when parseable.
    pub certificate_public_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Certificate parse error, when metadata could not be extracted.
    pub certificate_error: Option<String>,
}

#[derive(Clone, Copy)]
/// Adapter-backed store for SSO provider records.
pub struct SsoProviderStore<'a> {
    adapter: &'a dyn DbAdapter,
    model_name: &'a str,
    include_domain_verified: bool,
}

impl<'a> SsoProviderStore<'a> {
    /// Create a provider store over an OpenAuth adapter.
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self::new_with_model(adapter, SSO_PROVIDER_MODEL)
    }

    /// Create a provider store using a custom logical model name.
    pub fn new_with_model(adapter: &'a dyn DbAdapter, model_name: &'a str) -> Self {
        Self {
            adapter,
            model_name,
            include_domain_verified: false,
        }
    }

    /// Create a provider store from plugin options.
    pub fn new_with_options(
        adapter: &'a dyn DbAdapter,
        options: &'a crate::options::SsoOptions,
    ) -> Self {
        Self::new_with_model_and_domain_verification(
            adapter,
            &options.model_name,
            options.domain_verification.enabled,
        )
    }

    /// Create a provider store with explicit model and domain verification field support.
    pub fn new_with_model_and_domain_verification(
        adapter: &'a dyn DbAdapter,
        model_name: &'a str,
        include_domain_verified: bool,
    ) -> Self {
        Self {
            adapter,
            model_name,
            include_domain_verified,
        }
    }

    /// List all SSO providers.
    pub async fn list(&self) -> Result<Vec<SsoProviderRecord>, OpenAuthError> {
        let query = self.select_find_many(FindMany::new(self.model_name));
        self.adapter
            .find_many(query)
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    /// List SSO providers owned by a user.
    pub async fn list_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<SsoProviderRecord>, OpenAuthError> {
        let query = FindMany::new(self.model_name)
            .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())));
        self.adapter
            .find_many(self.select_find_many(query))
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    /// Find an SSO provider by stable provider id.
    pub async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        let query = FindOne::new(self.model_name).where_clause(provider_id_where(provider_id));
        self.adapter
            .find_one(self.select_find_one(query))
            .await?
            .map(record_from_db)
            .transpose()
    }

    /// Find the first SSO provider assigned to an organization.
    pub async fn find_by_organization_id(
        &self,
        organization_id: &str,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        let query = FindOne::new(self.model_name).where_clause(Where::new(
            "organizationId",
            DbValue::String(organization_id.to_owned()),
        ));
        self.adapter
            .find_one(self.select_find_one(query))
            .await?
            .map(record_from_db)
            .transpose()
    }

    /// Create an SSO provider record.
    pub async fn create(
        &self,
        input: CreateSsoProviderInput,
    ) -> Result<SsoProviderRecord, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut query = Create::new(self.model_name)
            .data("id", DbValue::String(generate_random_string(32)))
            .data("issuer", DbValue::String(input.issuer))
            .data("oidcConfig", optional_string(input.oidc_config))
            .data("samlConfig", optional_string(input.saml_config))
            .data("userId", DbValue::String(input.user_id))
            .data("providerId", DbValue::String(input.provider_id))
            .data("organizationId", optional_string(input.organization_id))
            .data("domain", DbValue::String(input.domain))
            .data("createdAt", DbValue::Timestamp(now))
            .data("updatedAt", DbValue::Timestamp(now))
            .force_allow_id();
        query = self.select_create(query);
        if let Some(domain_verified) = input.domain_verified {
            query = query.data("domainVerified", DbValue::Boolean(domain_verified));
        }

        record_from_db(self.adapter.create(query).await?)
    }

    /// Update a provider domain verification flag.
    pub async fn update_domain_verified(
        &self,
        provider_id: &str,
        verified: bool,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        self.adapter
            .update(
                Update::new(self.model_name)
                    .where_clause(provider_id_where(provider_id))
                    .data("domainVerified", DbValue::Boolean(verified))
                    .data("updatedAt", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    /// Partially update an SSO provider record.
    pub async fn update(
        &self,
        provider_id: &str,
        input: UpdateSsoProviderInput,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        let mut query = Update::new(self.model_name)
            .where_clause(provider_id_where(provider_id))
            .data("updatedAt", DbValue::Timestamp(OffsetDateTime::now_utc()));

        if let Some(issuer) = input.issuer {
            query = query.data("issuer", DbValue::String(issuer));
        }
        if let Some(domain) = input.domain {
            query = query.data("domain", DbValue::String(domain));
        }
        if let Some(organization_id) = input.organization_id {
            query = query.data("organizationId", DbValue::String(organization_id));
        }
        if let Some(oidc_config) = input.oidc_config {
            query = query.data("oidcConfig", optional_string(oidc_config));
        }
        if let Some(saml_config) = input.saml_config {
            query = query.data("samlConfig", optional_string(saml_config));
        }
        if let Some(domain_verified) = input.domain_verified {
            query = query.data("domainVerified", DbValue::Boolean(domain_verified));
        }

        self.adapter
            .update(query)
            .await?
            .map(record_from_db)
            .transpose()
    }

    /// Delete an SSO provider by provider id.
    pub async fn delete(&self, provider_id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(Delete::new(self.model_name).where_clause(provider_id_where(provider_id)))
            .await
    }

    fn select_create(&self, query: Create) -> Create {
        if self.include_domain_verified {
            query.select(SSO_PROVIDER_FIELDS_WITH_DOMAIN_VERIFIED)
        } else {
            query.select(SSO_PROVIDER_FIELDS)
        }
    }

    fn select_find_one(&self, query: FindOne) -> FindOne {
        if self.include_domain_verified {
            query.select(SSO_PROVIDER_FIELDS_WITH_DOMAIN_VERIFIED)
        } else {
            query.select(SSO_PROVIDER_FIELDS)
        }
    }

    fn select_find_many(&self, query: FindMany) -> FindMany {
        if self.include_domain_verified {
            query.select(SSO_PROVIDER_FIELDS_WITH_DOMAIN_VERIFIED)
        } else {
            query.select(SSO_PROVIDER_FIELDS)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Input used to create an SSO provider record.
pub struct CreateSsoProviderInput {
    /// Stable provider id.
    pub provider_id: String,
    /// Provider issuer.
    pub issuer: String,
    /// Provider domains.
    pub domain: String,
    /// Owner user id.
    pub user_id: String,
    /// Optional organization id.
    pub organization_id: Option<String>,
    /// Serialized OIDC configuration.
    pub oidc_config: Option<String>,
    /// Serialized SAML configuration.
    pub saml_config: Option<String>,
    /// Initial domain verification state.
    pub domain_verified: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Partial provider update input used by route handlers.
pub struct UpdateSsoProviderInput {
    /// Updated issuer.
    pub issuer: Option<String>,
    /// Updated domains.
    pub domain: Option<String>,
    /// Updated organization id.
    pub organization_id: Option<String>,
    /// Updated serialized OIDC config; `Some(None)` clears it.
    pub oidc_config: Option<Option<String>>,
    /// Updated serialized SAML config; `Some(None)` clears it.
    pub saml_config: Option<Option<String>>,
    /// Updated domain verification state.
    pub domain_verified: Option<bool>,
}

impl SsoProviderRecord {
    /// Convert the raw provider record into the public sanitized shape.
    pub fn sanitized_with_options(
        &self,
        base_url: &str,
        options: Option<&crate::options::SsoOptions>,
    ) -> SanitizedSsoProvider {
        let oidc_config = self
            .oidc_config
            .as_deref()
            .and_then(|value| serde_json::from_str::<OidcConfig>(value).ok())
            .map(|config| SanitizedOidcConfig {
                discovery_endpoint: config.discovery_endpoint,
                client_id_last_four: client_id_last_four(&config.client_id),
                pkce: config.pkce,
                authorization_endpoint: config.authorization_endpoint,
                token_endpoint: config.token_endpoint,
                user_info_endpoint: config.user_info_endpoint,
                jwks_endpoint: config.jwks_endpoint,
                revocation_endpoint: config.revocation_endpoint,
                end_session_endpoint: config.end_session_endpoint,
                introspection_endpoint: config.introspection_endpoint,
                token_endpoint_authentication: config.token_endpoint_authentication,
                scopes: config.scopes,
            });
        #[cfg(feature = "saml")]
        let saml_config = self
            .saml_config
            .as_deref()
            .and_then(|value| serde_json::from_str::<SamlConfig>(value).ok())
            .map(|config| {
                let certificate = certificate_metadata(&config.cert);
                SanitizedSamlConfig {
                    entry_point: config.entry_point,
                    callback_url: config.callback_url,
                    acs_url: config.acs_url,
                    audience: config.audience,
                    want_assertions_signed: config.want_assertions_signed,
                    authn_requests_signed: config.authn_requests_signed,
                    identifier_format: config.identifier_format,
                    signature_algorithm: config.signature_algorithm,
                    digest_algorithm: config.digest_algorithm,
                    certificate_sha256_fingerprint: certificate.sha256_fingerprint,
                    certificate_not_before: certificate.not_before,
                    certificate_not_after: certificate.not_after,
                    certificate_public_key_algorithm: certificate.public_key_algorithm,
                    certificate_error: certificate.parse_error,
                }
            });
        #[cfg(not(feature = "saml"))]
        let saml_config = None;
        let provider_type = if saml_config.is_some() {
            "saml"
        } else {
            "oidc"
        }
        .to_owned();
        #[cfg(feature = "oidc")]
        let redirect_uri = oidc_config.as_ref().and_then(|_| {
            options.map(|options| oidc_redirect_uri(base_url, &self.provider_id, options))
        });
        #[cfg(not(feature = "oidc"))]
        let redirect_uri = None;
        SanitizedSsoProvider {
            provider_id: self.provider_id.clone(),
            provider_type: provider_type.clone(),
            upstream_type: provider_type,
            issuer: self.issuer.clone(),
            domain: self.domain.clone(),
            organization_id: self.organization_id.clone(),
            domain_verified: self.domain_verified.unwrap_or(false),
            oidc_config,
            saml_config,
            redirect_uri,
            sp_metadata_url: format!(
                "{}/sso/saml2/sp/metadata?providerId={}",
                base_url.trim_end_matches('/'),
                url::form_urlencoded::byte_serialize(self.provider_id.as_bytes())
                    .collect::<String>()
            ),
        }
    }

    /// Convert the raw provider record into the public sanitized shape.
    pub fn sanitized(&self, base_url: &str) -> SanitizedSsoProvider {
        self.sanitized_with_options(base_url, None)
    }
}

fn provider_id_where(provider_id: &str) -> Where {
    Where::new("providerId", DbValue::String(provider_id.to_owned()))
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn record_from_db(record: DbRecord) -> Result<SsoProviderRecord, OpenAuthError> {
    Ok(SsoProviderRecord {
        id: required_string(&record, "id")?.to_owned(),
        issuer: required_string(&record, "issuer")?.to_owned(),
        oidc_config: optional_string_field(&record, "oidcConfig")?,
        saml_config: optional_string_field(&record, "samlConfig")?,
        user_id: required_string(&record, "userId")?.to_owned(),
        provider_id: required_string(&record, "providerId")?.to_owned(),
        organization_id: optional_string_field(&record, "organizationId")?,
        domain: required_string(&record, "domain")?.to_owned(),
        domain_verified: optional_bool_field(&record, "domainVerified")?,
        created_at: optional_timestamp_field(&record, "createdAt")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Json(value)) => serde_json::to_string(value)
            .map(Some)
            .map_err(|error| OpenAuthError::Adapter(format!("invalid JSON in `{field}`: {error}"))),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string, JSON, or null")),
    }
}

fn optional_bool_field(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "boolean or null")),
    }
}

fn optional_timestamp_field(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("sso provider record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "sso provider record field `{field}` must be {expected}"
    ))
}
