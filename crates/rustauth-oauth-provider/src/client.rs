use http::StatusCode;
use rustauth_core::context::AuthContext;
use rustauth_core::db::{DbAdapter, DbRecord, DbValue};
use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::error::OAuthProviderError;
use crate::models::SchemaClient;
use crate::options::{ClientReferenceInput, ResolvedOAuthProviderOptions};
use crate::schema::OAUTH_CLIENT_MODEL;
use crate::token::store_client_secret;
use crate::utils::{
    bool_value, create_query, find_by_string, json_value, now, random_id, random_string,
    split_scope, string, string_array, timestamp, update_by_string, validate_url,
};

/// OAuth 2.0 Dynamic Client Registration payload/response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_secret_expires_at: Option<i64>,
    pub scope: Option<String>,
    pub user_id: Option<String>,
    pub client_id_issued_at: Option<i64>,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub software_statement: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub public: Option<bool>,
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    pub disabled: Option<bool>,
    pub skip_consent: Option<bool>,
    pub enable_end_session: Option<bool>,
    pub require_pkce: Option<bool>,
    pub subject_type: Option<String>,
    pub reference_id: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOAuthClientInput {
    pub is_register: bool,
    pub user: Option<rustauth_core::db::User>,
    pub session: Option<rustauth_core::db::Session>,
}

pub async fn create_oauth_client(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    mut body: OAuthClient,
    input: CreateOAuthClientInput,
) -> Result<OAuthClient, RustAuthError> {
    if input.is_register && !options.allow_dynamic_client_registration {
        return Err(OAuthProviderError::access_denied("Client registration is disabled").into());
    }

    if input.is_register
        && input.user.is_none()
        && !options.allow_unauthenticated_client_registration
    {
        return Err(OAuthProviderError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Authentication required for client registration",
        )
        .into());
    }

    if body.scope.is_none() {
        let default_scopes =
            if input.is_register && !options.client_registration_default_scopes.is_empty() {
                &options.client_registration_default_scopes
            } else {
                &options.scopes
            };
        body.scope = Some(default_scopes.join(" "));
    }

    if input.user.is_none()
        && body
            .grant_types
            .as_ref()
            .is_some_and(|grants| grants.iter().any(|grant| grant == "client_credentials"))
    {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "client_credentials grant requires authenticated registration",
        )
        .into());
    }

    if input.user.is_none() {
        body.token_endpoint_auth_method = Some("none".to_owned());
        if body.client_type.as_deref() == Some("web") {
            body.client_type = None;
        }
    } else if body.token_endpoint_auth_method.is_none() {
        body.token_endpoint_auth_method = Some("client_secret_basic".to_owned());
    }
    if input.is_register {
        body.enable_end_session = None;
    }

    check_oauth_client(&body, options, input.is_register)?;
    let is_public = body.token_endpoint_auth_method.as_deref() == Some("none");
    let client_id = match &options.generate_client_id {
        Some(generator) => generator.generate().await?,
        None => random_string(32),
    };
    let raw_client_secret = if is_public {
        None
    } else {
        Some(match &options.generate_client_secret {
            Some(generator) => generator.generate().await?,
            None => random_string(32),
        })
    };
    let stored_secret = match raw_client_secret.as_deref() {
        Some(secret) => Some(store_client_secret(context, options, secret).await?),
        None => None,
    };
    let now = now();
    let reference_id = match &options.client_reference {
        Some(resolver) => {
            resolver
                .resolve(ClientReferenceInput {
                    user: input.user.clone(),
                    session: input.session.clone(),
                })
                .await?
        }
        None => None,
    };
    let mut schema = oauth_to_schema(&body);
    schema.id = Some(random_id("oauth_client"));
    schema.client_id = client_id.clone();
    schema.client_secret = stored_secret;
    schema.client_secret_expires_at = raw_client_secret.as_ref().map(|_| {
        if input.is_register {
            options
                .client_registration_client_secret_expiration
                .map(|seconds| now + Duration::seconds(seconds as i64))
                .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        } else {
            OffsetDateTime::UNIX_EPOCH
        }
    });
    schema.created_at = Some(now);
    schema.updated_at = Some(now);
    schema.public = Some(is_public);
    schema.disabled = None;
    schema.user_id = if reference_id.is_some() {
        None
    } else {
        input.user.as_ref().map(|user| user.id.clone())
    };
    schema.reference_id = reference_id;

    let created = adapter
        .create(create_query(
            OAUTH_CLIENT_MODEL,
            schema_client_record(&schema),
        ))
        .await?;
    let mut client = schema_to_oauth(&schema_client_from_record(created)?);
    client.client_secret = raw_client_secret
        .map(|secret| add_prefix(options.prefixes.client_secret.as_deref(), secret));
    Ok(client)
}

pub fn check_oauth_client(
    client: &OAuthClient,
    options: &ResolvedOAuthProviderOptions,
    is_register: bool,
) -> Result<(), RustAuthError> {
    let is_public = client.token_endpoint_auth_method.as_deref() == Some("none");
    if let Some(method) = client.token_endpoint_auth_method.as_deref() {
        if !matches!(
            method,
            "none" | "client_secret_basic" | "client_secret_post"
        ) {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "token_endpoint_auth_method is invalid",
            )
            .into());
        }
    }
    if is_register && client.skip_consent.is_some() {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "skip_consent cannot be set during dynamic client registration",
        )
        .into());
    }
    if let Some(client_type) = &client.client_type {
        if is_public && client_type != "native" && client_type != "user-agent-based" {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Type must be 'native' or 'user-agent-based' for public applications",
            )
            .into());
        }
        if !is_public && client_type != "web" {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "Type must be 'web' for confidential applications",
            )
            .into());
        }
    }

    let grant_types = client
        .grant_types
        .clone()
        .unwrap_or_else(|| vec!["authorization_code".to_owned()]);
    if grant_types.is_empty()
        || grant_types.iter().any(|grant| {
            !matches!(
                grant.as_str(),
                "authorization_code" | "client_credentials" | "refresh_token"
            )
        })
    {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "grant_types contains an unsupported grant",
        )
        .into());
    }
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
        && client.redirect_uris.as_ref().map_or(true, Vec::is_empty)
    {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Redirect URIs are required for authorization_code and implicit grant types",
        )
        .into());
    }
    for redirect_uri in client.redirect_uris.as_deref().unwrap_or_default() {
        if !validate_url(redirect_uri) {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect URI is invalid",
            )
            .into());
        }
    }
    if let Some(post_logout_redirect_uris) = client.post_logout_redirect_uris.as_ref() {
        if post_logout_redirect_uris.is_empty() {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "post_logout_redirect_uris must not be empty",
            )
            .into());
        }
        for redirect_uri in post_logout_redirect_uris {
            if !validate_url(redirect_uri) {
                return Err(OAuthProviderError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_redirect_uri",
                    "post_logout_redirect_uri is invalid",
                )
                .into());
            }
        }
    }

    let response_types = client
        .response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_owned()]);
    if response_types.is_empty()
        || response_types
            .iter()
            .any(|response_type| response_type != "code")
    {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "response_types contains an unsupported response type",
        )
        .into());
    }
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
        && !response_types
            .iter()
            .any(|response_type| response_type == "code")
    {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "When 'authorization_code' grant type is used, 'code' response type must be included",
        )
        .into());
    }

    if let Some(subject_type) = &client.subject_type {
        if subject_type != "public" && subject_type != "pairwise" {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "subject_type must be \"public\" or \"pairwise\"",
            )
            .into());
        }
        if subject_type == "pairwise" && options.pairwise_secret.is_none() {
            return Err(OAuthProviderError::new(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "pairwise subject_type requires server pairwiseSecret configuration",
            )
            .into());
        }
        if subject_type == "pairwise" {
            let mut hosts = client
                .redirect_uris
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|uri| url::Url::parse(uri).ok())
                .filter_map(|url| pairwise_sector(&url));
            if let Some(first_host) = hosts.next() {
                if hosts.any(|host| host != first_host) {
                    return Err(OAuthProviderError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_client_metadata",
                        "pairwise clients must use redirect URIs with the same host",
                    )
                    .into());
                }
            }
        }
    }

    let requested_scopes = split_scope(client.scope.as_deref());
    let allowed_scopes = if is_register && !options.client_registration_allowed_scopes.is_empty() {
        &options.client_registration_allowed_scopes
    } else {
        &options.scopes
    };
    for scope in requested_scopes {
        if !allowed_scopes.contains(&scope) {
            return Err(
                OAuthProviderError::invalid_scope(format!("cannot request scope {scope}")).into(),
            );
        }
    }

    if is_register && client.require_pkce == Some(false) {
        return Err(OAuthProviderError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "pkce is required for registered clients.",
        )
        .into());
    }

    Ok(())
}

pub async fn get_client(
    adapter: &dyn DbAdapter,
    client_id: &str,
) -> Result<Option<SchemaClient>, RustAuthError> {
    adapter
        .find_one(find_by_string(OAUTH_CLIENT_MODEL, "client_id", client_id))
        .await?
        .map(schema_client_from_record)
        .transpose()
}

pub async fn get_client_cached(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client_id: &str,
) -> Result<Option<SchemaClient>, RustAuthError> {
    if !options.cached_trusted_clients.contains(client_id) {
        return get_client(adapter, client_id).await;
    }
    if let Some(client) = options.trusted_client_cache.get(client_id)? {
        return Ok(Some(client));
    }
    let client = get_client(adapter, client_id).await?;
    if let Some(client) = client.as_ref() {
        options.trusted_client_cache.insert(client.clone())?;
    }
    Ok(client)
}

pub async fn update_client(
    adapter: &dyn DbAdapter,
    client_id: &str,
    data: DbRecord,
) -> Result<Option<SchemaClient>, RustAuthError> {
    adapter
        .update(update_by_string(
            OAUTH_CLIENT_MODEL,
            "client_id",
            client_id,
            data,
        ))
        .await?
        .map(schema_client_from_record)
        .transpose()
}

pub fn oauth_to_schema(input: &OAuthClient) -> SchemaClient {
    SchemaClient {
        id: None,
        client_id: input.client_id.clone().unwrap_or_default(),
        client_secret: input.client_secret.clone(),
        client_secret_expires_at: input
            .client_secret_expires_at
            .and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok()),
        disabled: input.disabled,
        skip_consent: input.skip_consent,
        enable_end_session: input.enable_end_session,
        subject_type: input.subject_type.clone(),
        scopes: input.scope.as_deref().map(|scope| split_scope(Some(scope))),
        user_id: input.user_id.clone(),
        created_at: input
            .client_id_issued_at
            .and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok()),
        updated_at: None,
        name: input.client_name.clone(),
        uri: input.client_uri.clone(),
        icon: input.logo_uri.clone(),
        contacts: input.contacts.clone(),
        tos: input.tos_uri.clone(),
        policy: input.policy_uri.clone(),
        software_id: input.software_id.clone(),
        software_version: input.software_version.clone(),
        software_statement: input.software_statement.clone(),
        redirect_uris: input.redirect_uris.clone().unwrap_or_default(),
        post_logout_redirect_uris: input.post_logout_redirect_uris.clone(),
        token_endpoint_auth_method: input.token_endpoint_auth_method.clone(),
        grant_types: input.grant_types.clone(),
        response_types: input.response_types.clone(),
        public: input.public,
        client_type: input.client_type.clone(),
        require_pkce: input.require_pkce,
        reference_id: input.reference_id.clone(),
        metadata: input.metadata.clone(),
    }
}

pub fn schema_to_oauth(input: &SchemaClient) -> OAuthClient {
    OAuthClient {
        client_id: Some(input.client_id.clone()),
        client_secret: input.client_secret.clone(),
        client_secret_expires_at: input.client_secret.as_ref().map(|_| {
            input
                .client_secret_expires_at
                .map(OffsetDateTime::unix_timestamp)
                .unwrap_or_default()
        }),
        scope: input.scopes.as_ref().map(|scopes| scopes.join(" ")),
        user_id: input.user_id.clone(),
        client_id_issued_at: input.created_at.map(OffsetDateTime::unix_timestamp),
        client_name: input.name.clone(),
        client_uri: input.uri.clone(),
        logo_uri: input.icon.clone(),
        contacts: input.contacts.clone(),
        tos_uri: input.tos.clone(),
        policy_uri: input.policy.clone(),
        software_id: input.software_id.clone(),
        software_version: input.software_version.clone(),
        software_statement: input.software_statement.clone(),
        redirect_uris: Some(input.redirect_uris.clone()),
        post_logout_redirect_uris: input.post_logout_redirect_uris.clone(),
        token_endpoint_auth_method: input.token_endpoint_auth_method.clone(),
        grant_types: input.grant_types.clone(),
        response_types: input.response_types.clone(),
        public: input.public,
        client_type: input.client_type.clone(),
        disabled: input.disabled,
        skip_consent: input.skip_consent,
        enable_end_session: input.enable_end_session,
        require_pkce: input.require_pkce,
        subject_type: input.subject_type.clone(),
        reference_id: input.reference_id.clone(),
        metadata: input.metadata.clone(),
    }
}

pub fn schema_client_record(input: &SchemaClient) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(
            input
                .id
                .clone()
                .unwrap_or_else(|| random_id("oauth_client")),
        ),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(input.client_id.clone()),
    );
    optional_string(&mut record, "client_secret", input.client_secret.clone());
    optional_timestamp(
        &mut record,
        "client_secret_expires_at",
        input.client_secret_expires_at,
    );
    optional_bool(&mut record, "disabled", input.disabled);
    optional_bool(&mut record, "skip_consent", input.skip_consent);
    optional_bool(&mut record, "enable_end_session", input.enable_end_session);
    optional_string(&mut record, "subject_type", input.subject_type.clone());
    optional_string_array(&mut record, "scopes", input.scopes.clone());
    optional_string(&mut record, "user_id", input.user_id.clone());
    optional_timestamp(&mut record, "created_at", input.created_at);
    optional_timestamp(&mut record, "updated_at", input.updated_at);
    optional_string(&mut record, "name", input.name.clone());
    optional_string(&mut record, "uri", input.uri.clone());
    optional_string(&mut record, "icon", input.icon.clone());
    optional_string_array(&mut record, "contacts", input.contacts.clone());
    optional_string(&mut record, "tos", input.tos.clone());
    optional_string(&mut record, "policy", input.policy.clone());
    optional_string(&mut record, "software_id", input.software_id.clone());
    optional_string(
        &mut record,
        "software_version",
        input.software_version.clone(),
    );
    optional_string(
        &mut record,
        "software_statement",
        input.software_statement.clone(),
    );
    record.insert(
        "redirect_uris".to_owned(),
        DbValue::StringArray(input.redirect_uris.clone()),
    );
    optional_string_array(
        &mut record,
        "post_logout_redirect_uris",
        input.post_logout_redirect_uris.clone(),
    );
    optional_string(
        &mut record,
        "token_endpoint_auth_method",
        input.token_endpoint_auth_method.clone(),
    );
    optional_string_array(&mut record, "grant_types", input.grant_types.clone());
    optional_string_array(&mut record, "response_types", input.response_types.clone());
    optional_bool(&mut record, "public", input.public);
    optional_string(&mut record, "type", input.client_type.clone());
    optional_bool(&mut record, "require_pkce", input.require_pkce);
    optional_string(&mut record, "reference_id", input.reference_id.clone());
    optional_json(&mut record, "metadata", input.metadata.clone());
    record
}

pub fn schema_client_from_record(record: DbRecord) -> Result<SchemaClient, RustAuthError> {
    let client_id = string(&record, "client_id")
        .ok_or_else(|| RustAuthError::Adapter("oauth client missing client_id".to_owned()))?;
    Ok(SchemaClient {
        id: string(&record, "id"),
        client_id,
        client_secret: string(&record, "client_secret"),
        client_secret_expires_at: timestamp(&record, "client_secret_expires_at"),
        disabled: bool_value(&record, "disabled"),
        skip_consent: bool_value(&record, "skip_consent"),
        enable_end_session: bool_value(&record, "enable_end_session"),
        subject_type: string(&record, "subject_type"),
        scopes: string_array(&record, "scopes"),
        user_id: string(&record, "user_id"),
        created_at: timestamp(&record, "created_at"),
        updated_at: timestamp(&record, "updated_at"),
        name: string(&record, "name"),
        uri: string(&record, "uri"),
        icon: string(&record, "icon"),
        contacts: string_array(&record, "contacts"),
        tos: string(&record, "tos"),
        policy: string(&record, "policy"),
        software_id: string(&record, "software_id"),
        software_version: string(&record, "software_version"),
        software_statement: string(&record, "software_statement"),
        redirect_uris: string_array(&record, "redirect_uris").unwrap_or_default(),
        post_logout_redirect_uris: string_array(&record, "post_logout_redirect_uris"),
        token_endpoint_auth_method: string(&record, "token_endpoint_auth_method"),
        grant_types: string_array(&record, "grant_types"),
        response_types: string_array(&record, "response_types"),
        public: bool_value(&record, "public"),
        client_type: string(&record, "type"),
        require_pkce: bool_value(&record, "require_pkce"),
        reference_id: string(&record, "reference_id"),
        metadata: json_value(&record, "metadata"),
    })
}

fn optional_string(record: &mut DbRecord, field: &str, value: Option<String>) {
    record.insert(
        field.to_owned(),
        value.map(DbValue::String).unwrap_or(DbValue::Null),
    );
}

fn optional_string_array(record: &mut DbRecord, field: &str, value: Option<Vec<String>>) {
    record.insert(
        field.to_owned(),
        value.map(DbValue::StringArray).unwrap_or(DbValue::Null),
    );
}

fn optional_bool(record: &mut DbRecord, field: &str, value: Option<bool>) {
    record.insert(
        field.to_owned(),
        value.map(DbValue::Boolean).unwrap_or(DbValue::Null),
    );
}

fn optional_timestamp(record: &mut DbRecord, field: &str, value: Option<OffsetDateTime>) {
    record.insert(
        field.to_owned(),
        value.map(DbValue::Timestamp).unwrap_or(DbValue::Null),
    );
}

fn optional_json(record: &mut DbRecord, field: &str, value: Option<Value>) {
    record.insert(
        field.to_owned(),
        value.map(DbValue::Json).unwrap_or(DbValue::Null),
    );
}

fn pairwise_sector(url: &url::Url) -> Option<String> {
    url.host_str().map(|host| match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn add_prefix(prefix: Option<&str>, value: String) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}{value}"),
        None => value,
    }
}
