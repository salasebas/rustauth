use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use openauth_core::auth::trusted_origins::OriginMatchSettings;
use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, User, Verification, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::session::DbSessionStore;
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_core::verification::{
    CreateVerificationInput, DbVerificationStore, UpdateVerificationInput,
};
use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use url::Url;

use super::options::{MagicLinkEmail, MagicLinkOptions, MagicLinkSendContext};
use super::payload::{
    parse_verify_query, SignInMagicLinkBody, VerificationPayload, VerifyMagicLinkQuery,
};
use super::response;
use super::session_response::{
    record_new_session, session_cookies, session_create_input, session_response_value,
};
use super::token::generate_magic_link_token;
use super::user_response::{additional_user_create_values, user_response_value};

pub(crate) fn sign_in_magic_link_endpoint(options: MagicLinkOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/magic-link",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInMagicLink")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_in_body_schema())
            .openapi(
                OpenApiOperation::new("signInWithMagicLink")
                    .description("Sign in with magic link")
                    .response(
                        "200",
                        serde_json::json!({
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": { "status": { "type": "boolean" } },
                                        "required": ["status"],
                                    },
                                },
                            },
                        }),
                    ),
            ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let body: SignInMagicLinkBody = parse_request_body(&request)?;
                validate_email(&body.email)?;
                let adapter = required_adapter(context)?;
                let token = match &options.generate_token {
                    Some(generate) => generate(&body.email).await?,
                    None => generate_magic_link_token(),
                };
                let identifier = options.store_token.identifier(&token).await?;
                let value = serde_json::to_string(&VerificationPayload {
                    email: body.email.clone(),
                    name: body.name.clone(),
                    attempt: 0,
                })
                .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                let expires_at = OffsetDateTime::now_utc()
                    .checked_add(Duration::seconds(effective_expires_in(&options) as i64))
                    .ok_or_else(|| OpenAuthError::Api("magic link expiry overflow".to_owned()))?;

                DbVerificationStore::new(adapter.as_ref())
                    .create_verification(CreateVerificationInput::new(
                        identifier, value, expires_at,
                    ))
                    .await?;

                let url = magic_link_url(context, &token, &body)?;
                (options.send_magic_link)(
                    MagicLinkEmail {
                        email: body.email,
                        url,
                        token,
                        metadata: body.metadata,
                    },
                    MagicLinkSendContext {
                        context,
                        request: &request,
                    },
                )
                .await?;

                response::json(
                    StatusCode::OK,
                    &serde_json::json!({ "status": true }),
                    Vec::new(),
                )
            })
        },
    )
}

pub(crate) fn verify_magic_link_endpoint(options: MagicLinkOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/magic-link/verify",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("verifyMagicLink")
            .openapi(
                OpenApiOperation::new("verifyMagicLink")
                    .description("Verify magic link")
                    .response(
                        "200",
                        serde_json::json!({
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "token": { "type": "string" },
                                            "session": { "$ref": "#/components/schemas/Session" },
                                            "user": { "$ref": "#/components/schemas/User" },
                                        },
                                    },
                                },
                            },
                        }),
                    ),
            ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let query = parse_verify_query(request.uri().query());
                if let Some(rejection) = validate_verify_origins(context, &request, &query)? {
                    return Ok(rejection);
                }
                let callback_url = resolve_callback_url(context, query.callback_url.as_deref())?;
                let error_url = resolve_callback_url(
                    context,
                    query.error_callback_url.as_deref().or(Some(&callback_url)),
                )?;
                let new_user_callback_url = resolve_callback_url(
                    context,
                    query
                        .new_user_callback_url
                        .as_deref()
                        .or(Some(&callback_url)),
                )?;

                let adapter = required_adapter(context)?;
                let identifier = options.store_token.identifier(&query.token).await?;
                let Some(verification) = find_verification(adapter.as_ref(), &identifier).await?
                else {
                    return response::redirect_with_error(&error_url, "INVALID_TOKEN");
                };
                if verification.expires_at <= OffsetDateTime::now_utc() {
                    DbVerificationStore::new(adapter.as_ref())
                        .delete_verification(&identifier)
                        .await?;
                    return response::redirect_with_error(&error_url, "EXPIRED_TOKEN");
                }

                let mut payload: VerificationPayload = serde_json::from_str(&verification.value)
                    .map_err(|error| {
                        OpenAuthError::Api(format!("invalid magic link payload: {error}"))
                    })?;
                if options.allowed_attempts.exceeded(payload.attempt) {
                    DbVerificationStore::new(adapter.as_ref())
                        .delete_verification(&identifier)
                        .await?;
                    return response::redirect_with_error(&error_url, "ATTEMPTS_EXCEEDED");
                }
                payload.attempt = payload.attempt.saturating_add(1);
                DbVerificationStore::new(adapter.as_ref())
                    .update_verification(
                        &identifier,
                        UpdateVerificationInput::new().value(
                            serde_json::to_string(&payload)
                                .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                        ),
                    )
                    .await?;

                let (user, is_new_user) =
                    match resolve_user(adapter.as_ref(), context, &options, &payload).await {
                        Ok(Some(user)) => user,
                        Ok(None) => {
                            return response::redirect_with_error(
                                &error_url,
                                "new_user_signup_disabled",
                            );
                        }
                        Err(_) => {
                            return response::redirect_with_error(
                                &error_url,
                                "failed_to_create_user",
                            );
                        }
                    };
                let expires_at = OffsetDateTime::now_utc()
                    .checked_add(Duration::seconds(context.session_config.expires_in as i64))
                    .ok_or_else(|| OpenAuthError::Api("session expiry overflow".to_owned()))?;
                let input = session_create_input(context, &request, user.id.clone(), expires_at);
                let session = match DbSessionStore::new(adapter.as_ref())
                    .create_session(input)
                    .await
                {
                    Ok(session) => session,
                    Err(_) => {
                        return response::redirect_with_error(
                            &error_url,
                            "failed_to_create_session",
                        );
                    }
                };
                record_new_session(&session, &user)?;
                let cookies = session_cookies(context, &session, &user)?;

                if query.callback_url.is_none() {
                    let token = session.token.clone();
                    let session =
                        session_response_value(adapter.as_ref(), context, &session).await?;
                    let user = user_response_value(adapter.as_ref(), context, &user).await?;
                    return response::json(
                        StatusCode::OK,
                        &VerifyResponse {
                            token,
                            user,
                            session,
                        },
                        cookies,
                    );
                }
                if is_new_user {
                    return response::redirect(&new_user_callback_url, cookies);
                }
                response::redirect(&callback_url, cookies)
            })
        },
    )
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    token: String,
    user: Value,
    session: Value,
}

fn required_adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::Api("magic link plugin requires a database adapter".to_owned())
    })
}

fn validate_email(email: &str) -> Result<(), OpenAuthError> {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(OpenAuthError::Api("invalid magic link email".to_owned()));
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(OpenAuthError::Api("invalid magic link email".to_owned()));
    }
    Ok(())
}

fn effective_expires_in(options: &MagicLinkOptions) -> u64 {
    if options.expires_in == 0 {
        60 * 5
    } else {
        options.expires_in
    }
}

fn sign_in_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("email", JsonSchemaType::String)
            .format("email")
            .description("Email address to send the magic link"),
        BodyField::optional("name", JsonSchemaType::String)
            .description("User display name for first-time registration"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("URL to redirect after magic link verification"),
        BodyField::optional("newUserCallbackURL", JsonSchemaType::String)
            .description("URL to redirect after new user signup"),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String)
            .description("URL to redirect after error"),
        BodyField::optional("metadata", JsonSchemaType::Object)
            .description("Additional metadata to pass to send_magic_link"),
    ])
}

fn magic_link_url(
    context: &AuthContext,
    token: &str,
    body: &SignInMagicLinkBody,
) -> Result<String, OpenAuthError> {
    let mut url = base_auth_url(context, "/magic-link/verify")?;
    url.query_pairs_mut()
        .append_pair("token", token)
        .append_pair("callbackURL", body.callback_url.as_deref().unwrap_or("/"));
    if let Some(callback) = &body.new_user_callback_url {
        url.query_pairs_mut()
            .append_pair("newUserCallbackURL", callback);
    }
    if let Some(callback) = &body.error_callback_url {
        url.query_pairs_mut()
            .append_pair("errorCallbackURL", callback);
    }
    Ok(url.to_string())
}

fn base_auth_url(context: &AuthContext, path: &str) -> Result<Url, OpenAuthError> {
    let mut base = Url::parse(&context.base_url)
        .map_err(|error| OpenAuthError::Api(format!("invalid base_url: {error}")))?;
    let base_url_path = base.path().trim_end_matches('/');
    let has_base_url_path = !base_url_path.is_empty();
    let base_path = if has_base_url_path {
        base_url_path
    } else {
        context.base_path.trim_end_matches('/')
    };
    base.set_path(&format!("{base_path}{path}"));
    Ok(base)
}

fn resolve_callback_url(
    context: &AuthContext,
    value: Option<&str>,
) -> Result<String, OpenAuthError> {
    let base = Url::parse(&context.base_url)
        .map_err(|error| OpenAuthError::Api(format!("invalid base_url: {error}")))?;
    let url = base
        .join(value.unwrap_or("/"))
        .map_err(|error| OpenAuthError::Api(format!("invalid callback URL: {error}")))?;
    Ok(url.to_string())
}

fn validate_verify_origins(
    context: &AuthContext,
    request: &http::Request<Vec<u8>>,
    query: &VerifyMagicLinkQuery,
) -> Result<Option<http::Response<Vec<u8>>>, OpenAuthError> {
    if context.options.advanced.disable_origin_check {
        return Ok(None);
    }
    for (label, value) in [
        ("callbackURL", query.callback_url.as_deref()),
        ("errorCallbackURL", query.error_callback_url.as_deref()),
        ("newUserCallbackURL", query.new_user_callback_url.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        if !context.is_trusted_origin_for_request(
            value,
            Some(OriginMatchSettings {
                allow_relative_paths: true,
            }),
            Some(request),
        )? {
            let (code, message) = match label {
                "callbackURL" => ("INVALID_CALLBACK_URL", "Invalid callbackURL"),
                "errorCallbackURL" => ("INVALID_ERROR_CALLBACK_URL", "Invalid errorCallbackURL"),
                "newUserCallbackURL" => (
                    "INVALID_NEW_USER_CALLBACK_URL",
                    "Invalid newUserCallbackURL",
                ),
                _ => ("INVALID_CALLBACK_URL", "Invalid callbackURL"),
            };
            return response::error(StatusCode::FORBIDDEN, code, message).map(Some);
        }
    }
    Ok(None)
}

async fn resolve_user(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    options: &MagicLinkOptions,
    payload: &VerificationPayload,
) -> Result<Option<(User, bool)>, OpenAuthError> {
    let users = DbUserStore::new(adapter);
    let Some(mut user) = users.find_user_by_email(&payload.email).await? else {
        if options.disable_sign_up {
            return Ok(None);
        }
        let user = users
            .create_user(
                CreateUserInput::new(payload.name.clone().unwrap_or_default(), &payload.email)
                    .email_verified(true)
                    .additional_fields(additional_user_create_values(context)),
            )
            .await?;
        return Ok(Some((user, true)));
    };

    if !user.email_verified {
        user = users
            .update_user_email_verified(&user.id, true)
            .await?
            .ok_or_else(|| OpenAuthError::Api("failed to verify magic link user".to_owned()))?;
    }

    Ok(Some((user, false)))
}

async fn find_verification(
    adapter: &dyn DbAdapter,
    identifier: &str,
) -> Result<Option<Verification>, OpenAuthError> {
    let Some(record) = adapter
        .find_one(FindOne::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(identifier.to_owned()),
        )))
        .await?
    else {
        return Ok(None);
    };
    verification_from_record(record).map(Some)
}

fn verification_from_record(record: DbRecord) -> Result<Verification, OpenAuthError> {
    Ok(Verification {
        id: string_field(&record, "id")?.to_owned(),
        identifier: string_field(&record, "identifier")?.to_owned(),
        value: string_field(&record, "value")?.to_owned(),
        expires_at: timestamp_field(&record, "expires_at")?,
        created_at: timestamp_field(&record, "created_at")?,
        updated_at: timestamp_field(&record, "updated_at")?,
    })
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "verification record field `{field}` must be string"
        ))),
    }
}

fn timestamp_field(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        _ => Err(OpenAuthError::Adapter(format!(
            "verification record field `{field}` must be timestamp"
        ))),
    }
}
