use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, FindOne, Update, Where,
};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::oidc::flow::oidc_redirect_uri;
use crate::options::{OidcConfig, SamlConfig};
use crate::schema::SSO_PROVIDER_MODEL;
use crate::utils::{certificate_metadata, client_id_last_four};

const SSO_PROVIDER_FIELDS: [&str; 10] = [
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
pub struct SsoProviderRecord {
    pub id: String,
    pub issuer: String,
    pub oidc_config: Option<String>,
    pub saml_config: Option<String>,
    pub user_id: String,
    pub provider_id: String,
    pub organization_id: Option<String>,
    pub domain: String,
    pub domain_verified: Option<bool>,
    pub created_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedSsoProvider {
    pub provider_id: String,
    pub provider_type: String,
    #[serde(rename = "type")]
    pub upstream_type: String,
    pub issuer: String,
    pub domain: String,
    pub organization_id: Option<String>,
    pub domain_verified: bool,
    pub oidc_config: Option<SanitizedOidcConfig>,
    pub saml_config: Option<SanitizedSamlConfig>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "redirectURI")]
    pub redirect_uri: Option<String>,
    pub sp_metadata_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedOidcConfig {
    pub discovery_endpoint: String,
    pub client_id_last_four: String,
    pub pkce: bool,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub user_info_endpoint: Option<String>,
    pub jwks_endpoint: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedSamlConfig {
    pub entry_point: String,
    pub callback_url: String,
    pub acs_url: Option<String>,
    pub audience: Option<String>,
    pub want_assertions_signed: bool,
    pub authn_requests_signed: bool,
    pub identifier_format: Option<String>,
    pub signature_algorithm: Option<String>,
    pub digest_algorithm: Option<String>,
    pub certificate_sha256_fingerprint: String,
    pub certificate_not_before: Option<String>,
    pub certificate_not_after: Option<String>,
    pub certificate_public_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_error: Option<String>,
}

#[derive(Clone, Copy)]
pub struct SsoProviderStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> SsoProviderStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn list(&self) -> Result<Vec<SsoProviderRecord>, OpenAuthError> {
        self.adapter
            .find_many(FindMany::new(SSO_PROVIDER_MODEL).select(SSO_PROVIDER_FIELDS))
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    pub async fn list_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<SsoProviderRecord>, OpenAuthError> {
        self.adapter
            .find_many(
                FindMany::new(SSO_PROVIDER_MODEL)
                    .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())))
                    .select(SSO_PROVIDER_FIELDS),
            )
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    pub async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(SSO_PROVIDER_MODEL)
                    .where_clause(provider_id_where(provider_id))
                    .select(SSO_PROVIDER_FIELDS),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub async fn find_by_organization_id(
        &self,
        organization_id: &str,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(SSO_PROVIDER_MODEL)
                    .where_clause(Where::new(
                        "organizationId",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .select(SSO_PROVIDER_FIELDS),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub async fn create(
        &self,
        input: CreateSsoProviderInput,
    ) -> Result<SsoProviderRecord, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut query = Create::new(SSO_PROVIDER_MODEL)
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
            .select(SSO_PROVIDER_FIELDS)
            .force_allow_id();
        if let Some(domain_verified) = input.domain_verified {
            query = query.data("domainVerified", DbValue::Boolean(domain_verified));
        }

        record_from_db(self.adapter.create(query).await?)
    }

    pub async fn update_domain_verified(
        &self,
        provider_id: &str,
        verified: bool,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        self.adapter
            .update(
                Update::new(SSO_PROVIDER_MODEL)
                    .where_clause(provider_id_where(provider_id))
                    .data("domainVerified", DbValue::Boolean(verified))
                    .data("updatedAt", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub async fn update(
        &self,
        provider_id: &str,
        input: UpdateSsoProviderInput,
    ) -> Result<Option<SsoProviderRecord>, OpenAuthError> {
        let mut query = Update::new(SSO_PROVIDER_MODEL)
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

    pub async fn delete(&self, provider_id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(Delete::new(SSO_PROVIDER_MODEL).where_clause(provider_id_where(provider_id)))
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSsoProviderInput {
    pub provider_id: String,
    pub issuer: String,
    pub domain: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub oidc_config: Option<String>,
    pub saml_config: Option<String>,
    pub domain_verified: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateSsoProviderInput {
    pub issuer: Option<String>,
    pub domain: Option<String>,
    pub organization_id: Option<String>,
    pub oidc_config: Option<Option<String>>,
    pub saml_config: Option<Option<String>>,
    pub domain_verified: Option<bool>,
}

impl SsoProviderRecord {
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
                scopes: config.scopes,
            });
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
        let provider_type = if saml_config.is_some() {
            "saml"
        } else {
            "oidc"
        }
        .to_owned();
        let redirect_uri = oidc_config.as_ref().and_then(|_| {
            options.map(|options| oidc_redirect_uri(base_url, &self.provider_id, options))
        });
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
