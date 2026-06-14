use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustauth_core::context::AuthContext;
use rustauth_core::crypto::buffer::constant_time_equal;
use rustauth_core::crypto::jwt as hs256_jwt;
use rustauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use rustauth_core::db::{DbAdapter, DbRecord, DbValue, DeleteMany, User, Where};
use rustauth_core::error::RustAuthError;
use serde_json::{json, Map, Value};
use time::{Duration, OffsetDateTime};

use crate::client::get_client_cached;
use crate::error::OAuthProviderError;
use crate::models::SchemaClient;
use crate::options::{
    ClientSecretHashInput, ClientSecretVerifyInput, CustomAccessTokenClaimsInput,
    CustomIdTokenClaimsInput, CustomTokenResponseFieldsInput, GrantType,
    RefreshTokenFormatDecodeOutput, RefreshTokenFormatEncodeInput, ResolvedOAuthProviderOptions,
    SecretStorage, TokenHashInput,
};
use crate::schema::{OAUTH_ACCESS_TOKEN_MODEL, OAUTH_REFRESH_TOKEN_MODEL};
use crate::utils::{
    create_query, delete_by_string, find_by_string, hmac_sha256_base64url, join_scope, now,
    random_id, random_string, sha256_base64url, string, string_array, timestamp, update_by_string,
    user_from_record, verify_hash,
};

mod claims;
mod introspection;
mod types;

pub(super) fn resolved_jwt_options(context: &AuthContext) -> rustauth_plugins::jwt::JwtOptions {
    rustauth_plugins::jwt::jwt_options_from_context(context)
        .map(|options| options.as_ref().clone())
        .unwrap_or_default()
}

pub(crate) use claims::user_normal_claims;
use claims::{create_id_token, find_user};
pub(crate) use claims::{resolve_subject_identifier, validate_id_token_hint};
pub(crate) use introspection::validate_access_token;
use introspection::{audiences_from_claims, client_id_from_audience, unverified_jwt_claims};
pub use introspection::{introspect_token_with_hint, revoke_token_with_hint};
use types::{AccessTokenInput, IdTokenInput};
pub(crate) use types::{
    AuthorizationCodeValue, RefreshTokenGrantInput, ValidatedAccessToken, ValidatedIdTokenHint,
};
pub use types::{TokenRequest, TokenResponse};

pub async fn store_client_secret(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
    secret: &str,
) -> Result<String, RustAuthError> {
    if let Some(resolver) = &options.hash_client_secret {
        return resolver
            .resolve(ClientSecretHashInput {
                secret: secret.to_owned(),
            })
            .await;
    }
    match options.store_client_secret {
        SecretStorage::Hashed => Ok(sha256_base64url(secret)),
        SecretStorage::Encrypted => symmetric_encrypt(context.secret.as_str(), secret),
        SecretStorage::Auto => unreachable!("options must be resolved before use"),
    }
}

pub async fn verify_client_secret(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
    stored_secret: &str,
    provided_secret: &str,
) -> Result<bool, RustAuthError> {
    let provided_secret = strip_prefix(options.prefixes.client_secret.as_deref(), provided_secret);
    if let Some(resolver) = &options.verify_client_secret_hash {
        return resolver
            .resolve(ClientSecretVerifyInput {
                secret: provided_secret.to_owned(),
                stored_hash: stored_secret.to_owned(),
            })
            .await;
    }
    if let Some(resolver) = &options.hash_client_secret {
        let hashed = resolver
            .resolve(ClientSecretHashInput {
                secret: provided_secret.to_owned(),
            })
            .await?;
        return Ok(constant_time_equal(hashed, stored_secret));
    }
    match options.store_client_secret {
        SecretStorage::Hashed => Ok(verify_hash(provided_secret, stored_secret)),
        SecretStorage::Encrypted => symmetric_decrypt(context.secret.as_str(), stored_secret)
            .map(|secret| constant_time_equal(secret, provided_secret)),
        SecretStorage::Auto => unreachable!("options must be resolved before use"),
    }
}

pub async fn store_token(
    options: &ResolvedOAuthProviderOptions,
    token: &str,
    token_type: &str,
) -> Result<String, RustAuthError> {
    let token = match token_type {
        "access_token" => strip_prefix(options.prefixes.opaque_access_token.as_deref(), token),
        "refresh_token" => strip_prefix(options.prefixes.refresh_token.as_deref(), token),
        _ => token,
    };
    if let Some(resolver) = &options.hash_token {
        return resolver
            .resolve(TokenHashInput {
                token: token.to_owned(),
                token_type: token_type.to_owned(),
            })
            .await;
    }
    match options.store_tokens {
        SecretStorage::Hashed | SecretStorage::Auto => Ok(sha256_base64url(token)),
        SecretStorage::Encrypted => Err(RustAuthError::InvalidConfig(
            "encrypted token storage is not supported; use hashed token storage".to_owned(),
        )),
    }
}

pub async fn decode_refresh_token(
    options: &ResolvedOAuthProviderOptions,
    token: &str,
) -> Result<RefreshTokenFormatDecodeOutput, RustAuthError> {
    let token = match options.prefixes.refresh_token.as_deref() {
        Some(prefix) => token.strip_prefix(prefix).ok_or_else(|| {
            OAuthProviderError::new(
                http::StatusCode::BAD_REQUEST,
                "invalid_token",
                "refresh token not found",
            )
        })?,
        None => token,
    };
    match &options.format_refresh_token {
        Some(formatter) => formatter.decode(token.to_owned()).await,
        None => Ok(RefreshTokenFormatDecodeOutput {
            session_id: None,
            token: token.to_owned(),
        }),
    }
}

pub async fn validate_client_credentials(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client_id: &str,
    client_secret: Option<&str>,
    scopes: &[String],
) -> Result<SchemaClient, RustAuthError> {
    let Some(client) = get_client_cached(adapter, options, client_id).await? else {
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
    if !is_public
        && client.client_secret_expires_at.is_some_and(|expires_at| {
            expires_at != OffsetDateTime::UNIX_EPOCH && expires_at <= now()
        })
    {
        return Err(OAuthProviderError::invalid_client("client secret is expired").into());
    }
    if client_secret.is_some() && client.client_secret.is_none() {
        return Err(OAuthProviderError::invalid_client(
            "public client, client secret should not be received",
        )
        .into());
    }
    if let (Some(provided), Some(stored)) = (client_secret, client.client_secret.as_deref()) {
        if !verify_client_secret(context, options, stored, provided).await? {
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

fn validate_client_grant(client: &SchemaClient, grant_type: &str) -> Result<(), RustAuthError> {
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
    resource: Vec<String>,
) -> Result<TokenResponse, RustAuthError> {
    let scopes = if requested_scopes.is_empty() {
        Vec::new()
    } else {
        reject_client_credentials_oidc_scopes(&requested_scopes)?;
        requested_scopes
    };
    let client =
        validate_client_credentials(context, adapter, options, client_id, client_secret, &scopes)
            .await?;
    validate_client_grant(&client, "client_credentials")?;
    let scopes = if scopes.is_empty() {
        match &client.scopes {
            Some(scopes) => scopes.clone(),
            None if !options.client_credential_grant_default_scopes.is_empty() => {
                options.client_credential_grant_default_scopes.clone()
            }
            None => options.scopes.clone(),
        }
    } else {
        scopes
    };
    reject_client_credentials_oidc_scopes(&scopes)?;
    let extra = resolve_custom_token_response_fields(
        adapter,
        options,
        &client,
        GrantType::ClientCredentials,
        None,
        scopes.clone(),
    )
    .await?;
    let mut response = create_access_token(
        context,
        adapter,
        options,
        &client,
        AccessTokenInput {
            user_id: None,
            session_id: None,
            reference_id: client.reference_id.clone(),
            scopes,
            machine_to_machine: true,
            resource,
        },
    )
    .await?;
    response.extra.extend(extra);
    Ok(response)
}

pub async fn create_authorization_code_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client_id: &str,
    client_secret: Option<&str>,
    code_value: AuthorizationCodeValue,
    resource: Vec<String>,
) -> Result<TokenResponse, RustAuthError> {
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
    ensure_authorization_subject_active(adapter, &code_value).await?;
    let extra = resolve_custom_token_response_fields(
        adapter,
        options,
        &client,
        GrantType::AuthorizationCode,
        Some(&code_value.user_id),
        code_value.scopes.clone(),
    )
    .await?;
    let mut response = create_access_token(
        context,
        adapter,
        options,
        &client,
        AccessTokenInput {
            user_id: Some(code_value.user_id.clone()),
            session_id: Some(code_value.session_id.clone()),
            reference_id: code_value.reference_id.clone(),
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
            auth_time: code_value.auth_time,
        },
    )
    .await?;
    if code_value
        .scopes
        .iter()
        .any(|scope| scope == "offline_access")
    {
        response.refresh_token = Some(
            create_refresh_token(CreateRefreshTokenInput {
                adapter,
                options,
                client: &client,
                user_id: &code_value.user_id,
                session_id: Some(&code_value.session_id),
                reference_id: code_value.reference_id.as_deref(),
                scopes: code_value.scopes.clone(),
                auth_time: code_value.auth_time,
            })
            .await?,
        );
    }
    response.extra.extend(extra);
    Ok(response)
}

pub(crate) async fn create_refresh_token_grant(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    input: RefreshTokenGrantInput<'_>,
) -> Result<TokenResponse, RustAuthError> {
    let decoded = decode_refresh_token(options, input.refresh_token).await?;
    let stored = store_token(options, &decoded.token, "refresh_token").await?;
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
    if string(&record, "client_id").as_deref() != Some(input.client_id) {
        return Err(OAuthProviderError::invalid_client("invalid client_id").into());
    }
    if timestamp(&record, "revoked").is_some() {
        if let Some(user_id) = string(&record, "user_id") {
            revoke_refresh_token_family(adapter, input.client_id, &user_id).await?;
        }
        return Err(OAuthProviderError::new(
            http::StatusCode::BAD_REQUEST,
            "invalid_grant",
            "invalid refresh token",
        )
        .into());
    }
    if timestamp(&record, "expires_at").map_or(true, |expires| expires <= now()) {
        return Err(OAuthProviderError::new(
            http::StatusCode::BAD_REQUEST,
            "invalid_grant",
            "invalid refresh token",
        )
        .into());
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
    let user_id = string(&record, "user_id").ok_or_else(|| {
        RustAuthError::Api("refresh token is missing required user_id".to_owned())
    })?;
    let session_id = string(&record, "session_id");
    let reference_id = string(&record, "reference_id");
    let auth_time = timestamp(&record, "auth_time");
    let extra = resolve_custom_token_response_fields(
        adapter,
        options,
        &client,
        GrantType::RefreshToken,
        Some(&user_id),
        scopes.clone(),
    )
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

    let new_refresh_token = create_refresh_token(CreateRefreshTokenInput {
        adapter,
        options,
        client: &client,
        user_id: &user_id,
        session_id: session_id.as_deref(),
        reference_id: reference_id.as_deref(),
        scopes: scopes.clone(),
        auth_time,
    })
    .await?;
    let mut response = create_access_token(
        context,
        adapter,
        options,
        &client,
        AccessTokenInput {
            user_id: Some(user_id.clone()),
            session_id: session_id.clone(),
            reference_id: reference_id.clone(),
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
    response.extra.extend(extra);
    Ok(response)
}

fn reject_client_credentials_oidc_scopes(scopes: &[String]) -> Result<(), RustAuthError> {
    let invalid = scopes
        .iter()
        .filter(|scope| is_oidc_user_scope(scope))
        .cloned()
        .collect::<Vec<_>>();
    if invalid.is_empty() {
        return Ok(());
    }
    Err(OAuthProviderError::invalid_scope(format!(
        "The following scopes are invalid: {}",
        invalid.join(", ")
    ))
    .into())
}

fn is_oidc_user_scope(scope: &str) -> bool {
    matches!(scope, "openid" | "profile" | "email" | "offline_access")
}

async fn resolve_custom_token_response_fields(
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client: &SchemaClient,
    grant_type: GrantType,
    user_id: Option<&str>,
    scopes: Vec<String>,
) -> Result<Map<String, Value>, RustAuthError> {
    let Some(resolver) = &options.custom_token_response_fields else {
        return Ok(Map::new());
    };
    let user = match user_id {
        Some(user_id) => find_user(adapter, user_id).await?,
        None => None,
    };
    let fields = resolver
        .resolve(CustomTokenResponseFieldsInput {
            grant_type,
            user,
            scopes,
            metadata: client.metadata.clone(),
        })
        .await?;
    let mut extra = Map::new();
    for (key, value) in fields {
        if !is_reserved_token_response_field(&key) {
            extra.insert(key, value);
        }
    }
    Ok(extra)
}

fn is_reserved_token_response_field(field: &str) -> bool {
    matches!(
        field,
        "access_token"
            | "token_type"
            | "expires_in"
            | "expires_at"
            | "refresh_token"
            | "scope"
            | "id_token"
    )
}

struct CreateRefreshTokenInput<'a> {
    adapter: &'a dyn DbAdapter,
    options: &'a ResolvedOAuthProviderOptions,
    client: &'a SchemaClient,
    user_id: &'a str,
    session_id: Option<&'a str>,
    reference_id: Option<&'a str>,
    scopes: Vec<String>,
    auth_time: Option<OffsetDateTime>,
}

async fn create_refresh_token(input: CreateRefreshTokenInput<'_>) -> Result<String, RustAuthError> {
    let iat = now();
    let expires_at = iat + Duration::seconds(input.options.refresh_token_expires_in as i64);
    let raw_token = match &input.options.generate_refresh_token {
        Some(generator) => generator.generate().await?,
        None => random_string(32),
    };
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(random_id("oauth_refresh_token")),
    );
    record.insert(
        "token".to_owned(),
        DbValue::String(store_token(input.options, &raw_token, "refresh_token").await?),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(input.client.client_id.clone()),
    );
    record.insert(
        "session_id".to_owned(),
        input
            .session_id
            .map(|session_id| DbValue::String(session_id.to_owned()))
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(input.user_id.to_owned()),
    );
    record.insert(
        "reference_id".to_owned(),
        input
            .reference_id
            .map(|reference_id| DbValue::String(reference_id.to_owned()))
            .unwrap_or(DbValue::Null),
    );
    record.insert("expires_at".to_owned(), DbValue::Timestamp(expires_at));
    record.insert("created_at".to_owned(), DbValue::Timestamp(iat));
    record.insert("revoked".to_owned(), DbValue::Null);
    record.insert(
        "auth_time".to_owned(),
        DbValue::Timestamp(input.auth_time.unwrap_or(iat)),
    );
    record.insert("scopes".to_owned(), DbValue::StringArray(input.scopes));
    input
        .adapter
        .create(create_query(OAUTH_REFRESH_TOKEN_MODEL, record))
        .await?;
    encode_refresh_token(input.options, raw_token, input.session_id).await
}

async fn ensure_authorization_subject_active(
    adapter: &dyn DbAdapter,
    code_value: &AuthorizationCodeValue,
) -> Result<(), RustAuthError> {
    if find_user(adapter, &code_value.user_id).await?.is_none() {
        return Err(OAuthProviderError::new(
            http::StatusCode::BAD_REQUEST,
            "invalid_user",
            "missing user, user may have been deleted",
        )
        .into());
    }
    let Some(session) = adapter
        .find_one(find_by_string("session", "id", &code_value.session_id))
        .await?
    else {
        return Err(OAuthProviderError::invalid_request("session no longer exists").into());
    };
    if string(&session, "user_id").as_deref() != Some(code_value.user_id.as_str())
        || timestamp(&session, "expires_at").map_or(true, |expires_at| expires_at <= now())
    {
        return Err(OAuthProviderError::invalid_request("session no longer exists").into());
    }
    Ok(())
}

async fn revoke_refresh_token_family(
    adapter: &dyn DbAdapter,
    client_id: &str,
    user_id: &str,
) -> Result<(), RustAuthError> {
    adapter
        .delete_many(
            DeleteMany::new(OAUTH_REFRESH_TOKEN_MODEL)
                .where_clause(Where::new(
                    "client_id",
                    DbValue::String(client_id.to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
        )
        .await?;
    Ok(())
}

async fn encode_refresh_token(
    options: &ResolvedOAuthProviderOptions,
    raw_token: String,
    session_id: Option<&str>,
) -> Result<String, RustAuthError> {
    let token = match &options.format_refresh_token {
        Some(formatter) => {
            formatter
                .encode(RefreshTokenFormatEncodeInput {
                    token: raw_token,
                    session_id: session_id.map(str::to_owned),
                })
                .await?
        }
        None => raw_token,
    };
    Ok(add_prefix(options.prefixes.refresh_token.as_deref(), token))
}

async fn create_access_token(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &ResolvedOAuthProviderOptions,
    client: &SchemaClient,
    input: AccessTokenInput,
) -> Result<TokenResponse, RustAuthError> {
    let iat = now();
    let default_lifetime = if input.machine_to_machine {
        options.m2m_access_token_expires_in
    } else {
        options.access_token_expires_in
    };
    let lifetime = access_token_lifetime(options, &input.scopes, default_lifetime);
    let expires_at = iat + Duration::seconds(lifetime as i64);
    if !input.resource.is_empty() && !options.disable_jwt_plugin {
        let mut claims = Map::new();
        let user = match input.user_id.as_deref() {
            Some(user_id) => find_user(adapter, user_id).await?,
            None => None,
        };
        if let Some(resolver) = &options.custom_access_token_claims {
            claims.extend(
                resolver
                    .resolve(CustomAccessTokenClaimsInput {
                        user: user.clone(),
                        reference_id: input.reference_id.clone(),
                        scopes: input.scopes.clone(),
                        resource: input.resource.clone(),
                        metadata: client.metadata.clone(),
                    })
                    .await?,
            );
        }
        if let Some(user_id) = &input.user_id {
            claims.insert("sub".to_owned(), Value::String(user_id.clone()));
        }
        if let Some(session_id) = &input.session_id {
            claims.insert("sid".to_owned(), Value::String(session_id.clone()));
        }
        let audience = if input.resource.len() == 1 {
            Value::String(input.resource[0].clone())
        } else {
            Value::Array(input.resource.into_iter().map(Value::String).collect())
        };
        claims.insert("aud".to_owned(), audience);
        claims.insert("azp".to_owned(), Value::String(client.client_id.clone()));
        claims.insert("scope".to_owned(), Value::String(join_scope(&input.scopes)));
        claims.insert("iss".to_owned(), Value::String(context.base_url.clone()));
        claims.insert("iat".to_owned(), Value::Number(iat.unix_timestamp().into()));
        claims.insert(
            "exp".to_owned(),
            Value::Number(expires_at.unix_timestamp().into()),
        );
        let access_token =
            rustauth_plugins::jwt::sign_jwt(context, claims, Some(resolved_jwt_options(context)))
                .await?;
        return Ok(TokenResponse {
            access_token,
            expires_in: (expires_at - iat).whole_seconds(),
            expires_at: expires_at.unix_timestamp(),
            token_type: "Bearer".to_owned(),
            refresh_token: None,
            scope: join_scope(&input.scopes),
            id_token: None,
            extra: Map::new(),
        });
    }
    let raw_token = match &options.generate_opaque_access_token {
        Some(generator) => generator.generate().await?,
        None => random_string(32),
    };
    let stored_token = store_token(options, &raw_token, "access_token").await?;
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
    record.insert(
        "reference_id".to_owned(),
        input
            .reference_id
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
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
        access_token: add_prefix(options.prefixes.opaque_access_token.as_deref(), raw_token),
        expires_in: (expires_at - iat).whole_seconds(),
        expires_at: expires_at.unix_timestamp(),
        token_type: "Bearer".to_owned(),
        refresh_token: None,
        scope: join_scope(&input.scopes),
        id_token: None,
        extra: Map::new(),
    })
}

fn strip_prefix<'a>(prefix: Option<&str>, value: &'a str) -> &'a str {
    match prefix {
        Some(prefix) => value.strip_prefix(prefix).unwrap_or(value),
        None => value,
    }
}

fn add_prefix(prefix: Option<&str>, value: String) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}{value}"),
        None => value,
    }
}

fn access_token_lifetime(
    options: &ResolvedOAuthProviderOptions,
    scopes: &[String],
    default_lifetime: u64,
) -> u64 {
    scopes
        .iter()
        .filter_map(|scope| options.scope_expirations.get(scope))
        .copied()
        .min()
        .map(|scope_lifetime| scope_lifetime.min(default_lifetime))
        .unwrap_or(default_lifetime)
}
