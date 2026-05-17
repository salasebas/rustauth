use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_core::context::AuthContext;
use openauth_core::crypto::jwt as hs256_jwt;
use openauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use openauth_core::db::{DbAdapter, DbRecord, DbValue, User};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::{Duration, OffsetDateTime};

use crate::client::get_client;
use crate::error::OAuthProviderError;
use crate::models::SchemaClient;
use crate::options::{ResolvedOAuthProviderOptions, SecretStorage};
use crate::schema::{OAUTH_ACCESS_TOKEN_MODEL, OAUTH_REFRESH_TOKEN_MODEL};
use crate::utils::{
    create_query, delete_by_string, find_by_string, hmac_sha256_base64url, join_scope, now,
    random_id, random_string, sha256_base64url, string, string_array, timestamp, update_by_string,
    user_from_record, verify_hash,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub expires_at: i64,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedAccessToken {
    pub active: bool,
    pub claims: Value,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedIdTokenHint {
    pub client: SchemaClient,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RefreshTokenGrantInput<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub refresh_token: &'a str,
    pub requested_scopes: Vec<String>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone)]
struct AccessTokenInput {
    user_id: Option<String>,
    session_id: Option<String>,
    scopes: Vec<String>,
    machine_to_machine: bool,
    resource: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct IdTokenInput<'a> {
    user_id: &'a str,
    session_id: Option<&'a str>,
    scopes: &'a [String],
    nonce: Option<&'a str>,
    auth_time: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthorizationCodeValue {
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub user_id: String,
    pub session_id: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub fn store_client_secret(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
    secret: &str,
) -> Result<String, OpenAuthError> {
    match options.store_client_secret {
        SecretStorage::Hashed => Ok(sha256_base64url(secret)),
        SecretStorage::Encrypted => symmetric_encrypt(context.secret.as_str(), secret),
        SecretStorage::Auto => unreachable!("options must be resolved before use"),
    }
}

pub fn verify_client_secret(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
    stored_secret: &str,
    provided_secret: &str,
) -> Result<bool, OpenAuthError> {
    match options.store_client_secret {
        SecretStorage::Hashed => Ok(verify_hash(provided_secret, stored_secret)),
        SecretStorage::Encrypted => {
            symmetric_decrypt(context.secret.as_str(), stored_secret).map(|secret| {
                openauth_core::crypto::buffer::constant_time_equal(secret, provided_secret)
            })
        }
        SecretStorage::Auto => unreachable!("options must be resolved before use"),
    }
}

pub fn store_token(
    options: &ResolvedOAuthProviderOptions,
    token: &str,
    _token_type: &str,
) -> Result<String, OpenAuthError> {
    match options.store_tokens {
        SecretStorage::Hashed | SecretStorage::Auto => Ok(sha256_base64url(token)),
        SecretStorage::Encrypted => Err(OpenAuthError::InvalidConfig(
            "encrypted token storage is not supported; use hashed token storage".to_owned(),
        )),
    }
}

pub fn decode_refresh_token(_options: &ResolvedOAuthProviderOptions, token: &str) -> String {
    token.to_owned()
}

pub async fn validate_client_credentials(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client_id: &str,
    client_secret: Option<&str>,
    scopes: &[String],
) -> Result<SchemaClient, OpenAuthError> {
    let Some(client) = get_client(adapter, client_id).await? else {
        return Err(OAuthProviderError::invalid_client("missing client").into());
    };
    if client.disabled == Some(true) {
        return Err(OAuthProviderError::invalid_client("client is disabled").into());
    }
    let is_public = client.public == Some(true)
        || client.token_endpoint_auth_method.as_deref() == Some("none")
        || matches!(
            client.client_type.as_deref(),
            Some("native" | "user-agent-based")
        );
    if !is_public && client_secret.is_none() {
        return Err(OAuthProviderError::invalid_client("client secret must be provided").into());
    }
    if client_secret.is_some() && client.client_secret.is_none() {
        return Err(OAuthProviderError::invalid_client(
            "public client, client secret should not be received",
        )
        .into());
    }
    if let (Some(provided), Some(stored)) = (client_secret, client.client_secret.as_deref()) {
        if !verify_client_secret(context, options, stored, provided)? {
            return Err(OAuthProviderError::unauthorized("invalid client_secret").into());
        }
    }
    if let Some(allowed_scopes) = &client.scopes {
        for scope in scopes {
            if !allowed_scopes.contains(scope) {
                return Err(OAuthProviderError::invalid_scope(format!(
                    "client does not allow scope {scope}"
                ))
                .into());
            }
        }
    }
    Ok(client)
}

fn validate_client_grant(client: &SchemaClient, grant_type: &str) -> Result<(), OpenAuthError> {
    if client
        .grant_types
        .as_ref()
        .is_some_and(|grant_types| !grant_types.iter().any(|grant| grant == grant_type))
    {
        return Err(OAuthProviderError::new(
            http::StatusCode::BAD_REQUEST,
            "unauthorized_client",
            format!("client is not allowed to use grant_type {grant_type}"),
        )
        .into());
    }
    Ok(())
}

pub async fn create_client_credentials_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client_id: &str,
    client_secret: Option<&str>,
    requested_scopes: Vec<String>,
    resource: Option<String>,
) -> Result<TokenResponse, OpenAuthError> {
    let scopes = if requested_scopes.is_empty() {
        Vec::new()
    } else {
        requested_scopes
    };
    let client =
        validate_client_credentials(context, adapter, options, client_id, client_secret, &scopes)
            .await?;
    validate_client_grant(&client, "client_credentials")?;
    let scopes = if scopes.is_empty() {
        client.scopes.clone().unwrap_or_default()
    } else {
        scopes
    };
    create_access_token(
        context,
        adapter,
        options,
        &client,
        AccessTokenInput {
            user_id: None,
            session_id: None,
            scopes,
            machine_to_machine: true,
            resource,
        },
    )
    .await
}

pub async fn create_authorization_code_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client_id: &str,
    client_secret: Option<&str>,
    code_value: AuthorizationCodeValue,
    resource: Option<String>,
) -> Result<TokenResponse, OpenAuthError> {
    let client = validate_client_credentials(
        context,
        adapter,
        options,
        client_id,
        client_secret,
        &code_value.scopes,
    )
    .await?;
    if client.client_id != code_value.client_id {
        return Err(OAuthProviderError::invalid_client("invalid client_id").into());
    }
    validate_client_grant(&client, "authorization_code")?;
    let mut response = create_access_token(
        context,
        adapter,
        options,
        &client,
        AccessTokenInput {
            user_id: Some(code_value.user_id.clone()),
            session_id: Some(code_value.session_id.clone()),
            scopes: code_value.scopes.clone(),
            machine_to_machine: false,
            resource,
        },
    )
    .await?;
    response.id_token = create_id_token(
        context,
        adapter,
        options,
        &client,
        IdTokenInput {
            user_id: &code_value.user_id,
            session_id: Some(&code_value.session_id),
            scopes: &code_value.scopes,
            nonce: code_value.nonce.as_deref(),
            auth_time: Some(now()),
        },
    )
    .await?;
    if code_value
        .scopes
        .iter()
        .any(|scope| scope == "offline_access")
    {
        response.refresh_token = Some(
            create_refresh_token(
                adapter,
                options,
                &client,
                &code_value.user_id,
                Some(&code_value.session_id),
                code_value.scopes,
            )
            .await?,
        );
    }
    Ok(response)
}

pub(crate) async fn create_refresh_token_grant(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    input: RefreshTokenGrantInput<'_>,
) -> Result<TokenResponse, OpenAuthError> {
    let stored = store_token(options, input.refresh_token, "refresh_token")?;
    let Some(record) = adapter
        .find_one(find_by_string(OAUTH_REFRESH_TOKEN_MODEL, "token", &stored))
        .await?
    else {
        return Err(OAuthProviderError::new(
            http::StatusCode::UNAUTHORIZED,
            "invalid_grant",
            "invalid refresh_token",
        )
        .into());
    };
    if timestamp(&record, "revoked").is_some()
        || timestamp(&record, "expires_at").map_or(true, |expires| expires <= now())
    {
        return Err(OAuthProviderError::new(
            http::StatusCode::UNAUTHORIZED,
            "invalid_grant",
            "refresh_token is expired or revoked",
        )
        .into());
    }
    if string(&record, "client_id").as_deref() != Some(input.client_id) {
        return Err(OAuthProviderError::invalid_client("invalid client_id").into());
    }

    let original_scopes = string_array(&record, "scopes").unwrap_or_default();
    let scopes = if input.requested_scopes.is_empty() {
        original_scopes.clone()
    } else {
        for scope in &input.requested_scopes {
            if !original_scopes.contains(scope) {
                return Err(OAuthProviderError::invalid_scope(format!(
                    "refresh token does not allow scope {scope}"
                ))
                .into());
            }
        }
        input.requested_scopes
    };
    let client = validate_client_credentials(
        context,
        adapter,
        options,
        input.client_id,
        input.client_secret,
        &scopes,
    )
    .await?;
    validate_client_grant(&client, "refresh_token")?;

    let mut revoke = DbRecord::new();
    revoke.insert("revoked".to_owned(), DbValue::Timestamp(now()));
    adapter
        .update(update_by_string(
            OAUTH_REFRESH_TOKEN_MODEL,
            "token",
            &stored,
            revoke,
        ))
        .await?;

    let user_id = string(&record, "user_id").ok_or_else(|| {
        OpenAuthError::Api("refresh token is missing required user_id".to_owned())
    })?;
    let session_id = string(&record, "session_id");
    let new_refresh_token = create_refresh_token(
        adapter,
        options,
        &client,
        &user_id,
        session_id.as_deref(),
        scopes.clone(),
    )
    .await?;
    let auth_time = timestamp(&record, "auth_time");
    let mut response = create_access_token(
        context,
        adapter,
        options,
        &client,
        AccessTokenInput {
            user_id: Some(user_id.clone()),
            session_id: session_id.clone(),
            scopes: scopes.clone(),
            machine_to_machine: false,
            resource: input.resource,
        },
    )
    .await?;
    response.refresh_token = Some(new_refresh_token);
    response.id_token = create_id_token(
        context,
        adapter,
        options,
        &client,
        IdTokenInput {
            user_id: &user_id,
            session_id: session_id.as_deref(),
            scopes: &scopes,
            nonce: None,
            auth_time,
        },
    )
    .await?;
    Ok(response)
}

pub async fn create_refresh_token(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client: &SchemaClient,
    user_id: &str,
    session_id: Option<&str>,
    scopes: Vec<String>,
) -> Result<String, OpenAuthError> {
    let iat = now();
    let expires_at = iat + Duration::seconds(options.refresh_token_expires_in as i64);
    let token = random_string(32);
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(random_id("oauth_refresh_token")),
    );
    record.insert(
        "token".to_owned(),
        DbValue::String(store_token(options, &token, "refresh_token")?),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(client.client_id.clone()),
    );
    record.insert(
        "session_id".to_owned(),
        session_id
            .map(|session_id| DbValue::String(session_id.to_owned()))
            .unwrap_or(DbValue::Null),
    );
    record.insert("user_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("reference_id".to_owned(), DbValue::Null);
    record.insert("expires_at".to_owned(), DbValue::Timestamp(expires_at));
    record.insert("created_at".to_owned(), DbValue::Timestamp(iat));
    record.insert("revoked".to_owned(), DbValue::Null);
    record.insert("auth_time".to_owned(), DbValue::Timestamp(iat));
    record.insert("scopes".to_owned(), DbValue::StringArray(scopes));
    adapter
        .create(create_query(OAUTH_REFRESH_TOKEN_MODEL, record))
        .await?;
    Ok(token)
}

async fn create_access_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client: &SchemaClient,
    input: AccessTokenInput,
) -> Result<TokenResponse, OpenAuthError> {
    let iat = now();
    let lifetime = if input.machine_to_machine {
        options.m2m_access_token_expires_in
    } else {
        options.access_token_expires_in
    };
    let expires_at = iat + Duration::seconds(lifetime as i64);
    if let Some(resource) = input.resource.filter(|resource| !resource.is_empty()) {
        if !options.disable_jwt_plugin {
            let mut claims = Map::new();
            if let Some(user_id) = &input.user_id {
                claims.insert("sub".to_owned(), Value::String(user_id.clone()));
            }
            if let Some(session_id) = &input.session_id {
                claims.insert("sid".to_owned(), Value::String(session_id.clone()));
            }
            claims.insert("aud".to_owned(), Value::String(resource));
            claims.insert("azp".to_owned(), Value::String(client.client_id.clone()));
            claims.insert("scope".to_owned(), Value::String(join_scope(&input.scopes)));
            claims.insert("iss".to_owned(), Value::String(context.base_url.clone()));
            claims.insert("iat".to_owned(), Value::Number(iat.unix_timestamp().into()));
            claims.insert(
                "exp".to_owned(),
                Value::Number(expires_at.unix_timestamp().into()),
            );
            let access_token = openauth_plugins::jwt::sign_jwt(context, claims, None).await?;
            return Ok(TokenResponse {
                access_token,
                expires_in: (expires_at - iat).whole_seconds(),
                expires_at: expires_at.unix_timestamp(),
                token_type: "Bearer".to_owned(),
                refresh_token: None,
                scope: join_scope(&input.scopes),
                id_token: None,
            });
        }
    }
    let token = random_string(32);
    let stored_token = store_token(options, &token, "access_token")?;
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(random_id("oauth_access_token")),
    );
    record.insert("token".to_owned(), DbValue::String(stored_token));
    record.insert(
        "client_id".to_owned(),
        DbValue::String(client.client_id.clone()),
    );
    record.insert(
        "session_id".to_owned(),
        input
            .session_id
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "user_id".to_owned(),
        input.user_id.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert("reference_id".to_owned(), DbValue::Null);
    record.insert("refresh_id".to_owned(), DbValue::Null);
    record.insert("expires_at".to_owned(), DbValue::Timestamp(expires_at));
    record.insert("created_at".to_owned(), DbValue::Timestamp(iat));
    record.insert(
        "scopes".to_owned(),
        DbValue::StringArray(input.scopes.clone()),
    );
    adapter
        .create(create_query(OAUTH_ACCESS_TOKEN_MODEL, record))
        .await?;
    Ok(TokenResponse {
        access_token: token,
        expires_in: (expires_at - iat).whole_seconds(),
        expires_at: expires_at.unix_timestamp(),
        token_type: "Bearer".to_owned(),
        refresh_token: None,
        scope: join_scope(&input.scopes),
        id_token: None,
    })
}

async fn create_id_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client: &SchemaClient,
    input: IdTokenInput<'_>,
) -> Result<Option<String>, OpenAuthError> {
    if !input.scopes.iter().any(|scope| scope == "openid") {
        return Ok(None);
    }
    if options.disable_jwt_plugin && client.client_secret.is_none() {
        return Ok(None);
    }
    let Some(user) = find_user(adapter, input.user_id).await? else {
        return Err(OAuthProviderError::invalid_request("user not found").into());
    };
    let iat = now();
    let exp = iat + Duration::seconds(options.id_token_expires_in as i64);
    let mut claims = user_normal_claims(&user, input.scopes);
    claims.insert(
        "sub".to_owned(),
        Value::String(resolve_subject_identifier(input.user_id, client, options)?),
    );
    claims.insert("iss".to_owned(), Value::String(context.base_url.clone()));
    claims.insert("aud".to_owned(), Value::String(client.client_id.clone()));
    claims.insert("iat".to_owned(), Value::Number(iat.unix_timestamp().into()));
    claims.insert("exp".to_owned(), Value::Number(exp.unix_timestamp().into()));
    claims.insert(
        "acr".to_owned(),
        Value::String("urn:mace:incommon:iap:bronze".to_owned()),
    );
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".to_owned(), Value::String(nonce.to_owned()));
    }
    if client.enable_end_session == Some(true) {
        if let Some(session_id) = input.session_id {
            claims.insert("sid".to_owned(), Value::String(session_id.to_owned()));
        }
    }
    if let Some(auth_time) = input.auth_time {
        claims.insert(
            "auth_time".to_owned(),
            Value::Number(auth_time.unix_timestamp().into()),
        );
    }

    if options.disable_jwt_plugin {
        let stored_secret = client.client_secret.as_deref().ok_or_else(|| {
            OpenAuthError::Api("client_secret is required for HS256 id_token".to_owned())
        })?;
        let secret = symmetric_decrypt(context.secret.as_str(), stored_secret)?;
        return hs256_jwt::sign_jwt(&claims, &secret, options.id_token_expires_in as i64).map(Some);
    }

    openauth_plugins::jwt::sign_jwt(context, claims, None)
        .await
        .map(Some)
}

fn user_normal_claims(user: &User, scopes: &[String]) -> Map<String, Value> {
    let mut claims = Map::new();
    if scopes.iter().any(|scope| scope == "profile") {
        claims.insert("name".to_owned(), Value::String(user.name.clone()));
        if let Some(image) = &user.image {
            claims.insert("picture".to_owned(), Value::String(image.clone()));
        }
        let names = user
            .name
            .split_whitespace()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if names.len() > 1 {
            claims.insert(
                "given_name".to_owned(),
                Value::String(names[..names.len() - 1].join(" ")),
            );
            claims.insert(
                "family_name".to_owned(),
                Value::String(names[names.len() - 1].to_owned()),
            );
        }
    }
    if scopes.iter().any(|scope| scope == "email") {
        claims.insert("email".to_owned(), Value::String(user.email.clone()));
        claims.insert(
            "email_verified".to_owned(),
            Value::Bool(user.email_verified),
        );
    }
    claims
}

async fn find_user(adapter: &dyn DbAdapter, user_id: &str) -> Result<Option<User>, OpenAuthError> {
    adapter
        .find_one(find_by_string("user", "id", user_id))
        .await?
        .map(user_from_record)
        .transpose()
}

pub(crate) fn resolve_subject_identifier(
    user_id: &str,
    client: &SchemaClient,
    options: &ResolvedOAuthProviderOptions,
) -> Result<String, OpenAuthError> {
    let Some(secret) = options.pairwise_secret.as_deref() else {
        return Ok(user_id.to_owned());
    };
    if client.subject_type.as_deref() != Some("pairwise") {
        return Ok(user_id.to_owned());
    }
    let sector = sector_identifier(client)?;
    hmac_sha256_base64url(&format!("{sector}.{user_id}"), secret)
}

pub(crate) async fn validate_id_token_hint(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
    client_id_hint: Option<&str>,
) -> Result<ValidatedIdTokenHint, OAuthProviderError> {
    let unverified = unverified_jwt_claims(token).ok_or_else(|| {
        OAuthProviderError::new(
            http::StatusCode::UNAUTHORIZED,
            "invalid_token",
            "invalid id token",
        )
    })?;
    let client_id = client_id_hint
        .map(str::to_owned)
        .or_else(|| client_id_from_audience(&unverified))
        .ok_or_else(|| OAuthProviderError::invalid_request("id token missing audience"))?;
    let Some(client) = get_client(adapter, &client_id)
        .await
        .map_err(|error| OAuthProviderError::invalid_request(error.to_string()))?
    else {
        return Err(OAuthProviderError::invalid_client("client doesn't exist"));
    };
    if client.disabled == Some(true) {
        return Err(OAuthProviderError::invalid_client("client is disabled"));
    }
    if client.enable_end_session != Some(true) {
        return Err(OAuthProviderError::unauthorized("client unable to logout"));
    }

    let claims = if options.disable_jwt_plugin {
        let stored_secret = client
            .client_secret
            .as_deref()
            .ok_or_else(|| OAuthProviderError::invalid_client("missing required credentials"))?;
        let secret = symmetric_decrypt(context.secret.as_str(), stored_secret).map_err(|_| {
            OAuthProviderError::new(
                http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid id token",
            )
        })?;
        let value: Value = hs256_jwt::verify_jwt(token, &secret)
            .map_err(|_| {
                OAuthProviderError::new(
                    http::StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "invalid id token",
                )
            })?
            .ok_or_else(|| {
                OAuthProviderError::new(
                    http::StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "invalid id token",
                )
            })?;
        match value {
            Value::Object(claims) => claims,
            _ => return Err(OAuthProviderError::invalid_request("missing payload")),
        }
    } else {
        let mut jwt_options = openauth_plugins::jwt::JwtOptions::default();
        jwt_options.jwt.audience = Some(vec![client_id.clone()]);
        openauth_plugins::jwt::verify_jwt_with_options(
            context,
            token,
            &jwt_options,
            Some(&context.base_url),
        )
        .await
        .map_err(|_| {
            OAuthProviderError::new(
                http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid id token",
            )
        })?
        .ok_or_else(|| {
            OAuthProviderError::new(
                http::StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid id token",
            )
        })?
    };

    if claims.get("iss").and_then(Value::as_str) != Some(context.base_url.as_str()) {
        return Err(OAuthProviderError::invalid_request("invalid issuer"));
    }
    let audiences = audiences_from_claims(&claims)
        .ok_or_else(|| OAuthProviderError::invalid_request("id token missing audience"))?;
    if !audiences.iter().any(|audience| audience == &client_id) {
        return Err(OAuthProviderError::invalid_request("audience mismatch"));
    }
    let session_id = claims
        .get("sid")
        .and_then(Value::as_str)
        .ok_or_else(|| OAuthProviderError::invalid_request("id token missing session"))?
        .to_owned();

    Ok(ValidatedIdTokenHint { client, session_id })
}

fn sector_identifier(client: &SchemaClient) -> Result<String, OpenAuthError> {
    let uri = client
        .redirect_uris
        .first()
        .ok_or_else(|| OpenAuthError::Api("client has no redirect URIs".to_owned()))?;
    let url = url::Url::parse(uri).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| OpenAuthError::Api("redirect URI has no host".to_owned()))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

pub(crate) async fn validate_access_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<Option<ValidatedAccessToken>, OpenAuthError> {
    let stored = store_token(options, token, "access_token")?;
    if let Some(record) = adapter
        .find_one(find_by_string(OAUTH_ACCESS_TOKEN_MODEL, "token", &stored))
        .await?
    {
        let active = timestamp(&record, "expires_at").is_some_and(|expires| expires > now());
        let client_id = string(&record, "client_id");
        let user_id = string(&record, "user_id");
        let scopes = string_array(&record, "scopes").unwrap_or_default();
        let sub = match (&client_id, &user_id) {
            (Some(client_id), Some(user_id)) => match get_client(adapter, client_id).await? {
                Some(client) => Some(resolve_subject_identifier(user_id, &client, options)?),
                None => Some(user_id.clone()),
            },
            _ => user_id.clone(),
        };
        return Ok(Some(ValidatedAccessToken {
            active,
            user_id,
            client_id: client_id.clone(),
            scopes: scopes.clone(),
            claims: json!({
            "active": active,
            "token_type": "access_token",
            "client_id": client_id,
            "sub": sub,
            "sid": string(&record, "session_id"),
            "exp": timestamp(&record, "expires_at").map(OffsetDateTime::unix_timestamp),
            "iat": timestamp(&record, "created_at").map(OffsetDateTime::unix_timestamp),
            "scope": join_scope(&scopes),
            }),
        }));
    }
    if !options.disable_jwt_plugin {
        if let Some(unverified) = unverified_jwt_claims(token) {
            let mut jwt_options = openauth_plugins::jwt::JwtOptions::default();
            jwt_options.jwt.audience = audiences_from_claims(&unverified);
            if let Some(claims) = openauth_plugins::jwt::verify_jwt_with_options(
                context,
                token,
                &jwt_options,
                Some(&context.base_url),
            )
            .await?
            {
                let scopes = claims
                    .get("scope")
                    .and_then(Value::as_str)
                    .map(|scope| {
                        scope
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let user_id = claims.get("sub").and_then(Value::as_str).map(str::to_owned);
                let client_id = claims.get("azp").and_then(Value::as_str).map(str::to_owned);
                let mut response = Value::Object(claims);
                if let Value::Object(map) = &mut response {
                    map.insert("active".to_owned(), Value::Bool(true));
                    map.insert(
                        "token_type".to_owned(),
                        Value::String("access_token".to_owned()),
                    );
                    if let Some(client_id) = &client_id {
                        map.insert("client_id".to_owned(), Value::String(client_id.clone()));
                    }
                }
                return Ok(Some(ValidatedAccessToken {
                    active: true,
                    claims: response,
                    user_id,
                    client_id,
                    scopes,
                }));
            }
        }
    }
    Ok(None)
}

pub async fn introspect_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<serde_json::Value, OpenAuthError> {
    if let Some(validated) = validate_access_token(context, adapter, options, token).await? {
        return Ok(validated.claims);
    }
    let stored = store_token(options, token, "refresh_token")?;
    if let Some(record) = adapter
        .find_one(find_by_string(OAUTH_REFRESH_TOKEN_MODEL, "token", &stored))
        .await?
    {
        let active = timestamp(&record, "revoked").is_none()
            && timestamp(&record, "expires_at").is_some_and(|expires| expires > now());
        return Ok(serde_json::json!({
            "active": active,
            "token_type": "refresh_token",
            "client_id": string(&record, "client_id"),
            "sub": string(&record, "user_id"),
            "sid": string(&record, "session_id"),
            "exp": timestamp(&record, "expires_at").map(OffsetDateTime::unix_timestamp),
            "iat": timestamp(&record, "created_at").map(OffsetDateTime::unix_timestamp),
            "scope": string_array(&record, "scopes").map(|scopes| scopes.join(" ")),
        }));
    }
    Ok(serde_json::json!({ "active": false }))
}

fn unverified_jwt_claims(token: &str) -> Option<Map<String, Value>> {
    let payload = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    match serde_json::from_slice::<Value>(&payload).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn audiences_from_claims(claims: &Map<String, Value>) -> Option<Vec<String>> {
    match claims.get("aud") {
        Some(Value::String(audience)) => Some(vec![audience.clone()]),
        Some(Value::Array(audiences)) => Some(
            audiences
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        _ => None,
    }
}

fn client_id_from_audience(claims: &Map<String, Value>) -> Option<String> {
    audiences_from_claims(claims).and_then(|audiences| audiences.into_iter().next())
}

pub async fn revoke_token(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<(), OpenAuthError> {
    let stored = store_token(options, token, "access_token")?;
    adapter
        .delete(delete_by_string(OAUTH_ACCESS_TOKEN_MODEL, "token", &stored))
        .await?;
    let mut revoke = DbRecord::new();
    revoke.insert("revoked".to_owned(), DbValue::Timestamp(now()));
    adapter
        .update(update_by_string(
            OAUTH_REFRESH_TOKEN_MODEL,
            "token",
            &stored,
            revoke,
        ))
        .await?;
    Ok(())
}
