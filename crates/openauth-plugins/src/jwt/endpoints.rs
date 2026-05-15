use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, ApiRequest, ApiResponse, AuthEndpointOptions};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::request_state::{set_current_session, set_current_session_user};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};

use super::claims::JwtClaims;
use super::keys::{public_jwk_value, Jwks};
use super::{adapter, keys, sign, verify, JwtOptions, JwtSessionContext};

pub(crate) fn jwks_endpoint(options: Arc<JwtOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    let path = options.jwks.jwks_path.clone();
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new().operation_id("getJSONWebKeySet"),
        move |context, _request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                if options.jwks.remote_url.is_some() {
                    return json_response(StatusCode::NOT_FOUND, &json!({"code": "NOT_FOUND"}));
                }
                let jwks = get_or_create_public_jwks(context, &options).await?;
                json_response(StatusCode::OK, &jwks)
            })
        },
    )
}

pub(crate) fn token_endpoint(options: Arc<JwtOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/token",
        Method::GET,
        AuthEndpointOptions::new().operation_id("getJSONWebToken"),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some((session, user)) = session_user(context, &request).await? else {
                    return json_response(
                        StatusCode::UNAUTHORIZED,
                        &json!({"code": "UNAUTHORIZED"}),
                    );
                };
                let token = sign_session_token(context, &options, session, user).await?;
                json_response(StatusCode::OK, &json!({ "token": token }))
            })
        },
    )
}

pub(crate) fn sign_jwt_endpoint(options: Arc<JwtOptions>) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-jwt",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signJWT")
            .server_only(),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: SignJwtBody = parse_json(&request)?;
                let token = sign::sign_jwt_with_options(context, body.payload, &options).await?;
                json_response(StatusCode::OK, &json!({ "token": token }))
            })
        },
    )
}

pub(crate) fn verify_jwt_endpoint(
    options: Arc<JwtOptions>,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/verify-jwt",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("verifyJWT")
            .server_only(),
        move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: VerifyJwtBody = parse_json(&request)?;
                let payload = verify::verify_jwt_with_options(
                    context,
                    &body.token,
                    &options,
                    body.issuer.as_deref(),
                )
                .await?;
                json_response(StatusCode::OK, &json!({ "payload": payload }))
            })
        },
    )
}

async fn get_or_create_public_jwks(
    context: &AuthContext,
    options: &JwtOptions,
) -> Result<Jwks, OpenAuthError> {
    let mut keys = adapter::get_all_keys(context, options).await?;
    if keys.is_empty() {
        let key = super::crypto::encrypt_private_key(
            context,
            keys::generate_jwk(options)?,
            options.jwks.disable_private_key_encryption,
        )?;
        adapter::create_jwk(context, options, key).await?;
        keys = adapter::get_all_keys(context, options).await?;
    }
    let now = time::OffsetDateTime::now_utc();
    let grace = time::Duration::seconds(options.jwks.grace_period);
    let public = keys
        .into_iter()
        .filter(|key| match key.expires_at {
            Some(expires_at) => expires_at + grace > now,
            None => true,
        })
        .map(|key| public_jwk_value(&key, options))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Jwks { keys: public })
}

pub(crate) async fn sign_session_token(
    context: &AuthContext,
    options: &JwtOptions,
    session: openauth_core::db::Session,
    user: openauth_core::db::User,
) -> Result<String, OpenAuthError> {
    let session_context = JwtSessionContext {
        session,
        user: user.clone(),
    };
    let mut claims = if let Some(define_payload) = &options.jwt.define_payload {
        define_payload(&session_context).await?
    } else {
        let Value::Object(map) =
            serde_json::to_value(&user).map_err(|error| OpenAuthError::Api(error.to_string()))?
        else {
            return Err(OpenAuthError::Api(
                "user must serialize to object".to_owned(),
            ));
        };
        map
    };
    let subject = if let Some(get_subject) = &options.jwt.get_subject {
        get_subject(&session_context).await?
    } else {
        user.id
    };
    claims.insert("sub".to_owned(), Value::String(subject));
    sign::sign_jwt_with_options(context, claims, options).await
}

async fn session_user(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(openauth_core::db::Session, openauth_core::db::User)>, OpenAuthError> {
    let Some(adapter) = context.adapter() else {
        return Ok(None);
    };
    let Some(result) = SessionAuth::new(adapter.as_ref(), context)
        .get_session(GetSessionInput::new(
            cookie_header(request).unwrap_or_default(),
        ))
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    if openauth_core::context::request_state::has_request_state() {
        set_current_session(session.clone(), user.clone())?;
        set_current_session_user(
            serde_json::to_value(&user).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        )?;
    }
    Ok(Some((session, user)))
}

fn cookie_header(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn parse_json<T>(request: &ApiRequest) -> Result<T, OpenAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(request.body()).map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn json_response<T>(status: StatusCode, body: &T) -> Result<ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct SignJwtBody {
    payload: JwtClaims,
}

#[derive(Debug, Deserialize)]
struct VerifyJwtBody {
    token: String,
    issuer: Option<String>,
}
