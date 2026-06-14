use std::sync::Arc;

use http::{header, Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, ApiRequest, ApiResponse, AuthEndpointOptions};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::request_state::{set_current_session, set_current_session_user};
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};

use super::claims::JwtClaims;
use super::keys::{public_jwk_value, Jwks};
use super::{
    adapter, keys, sign, verify, JwkAlgorithm, JwtJwksOptions, JwtOptions, JwtSessionContext,
    JwtSigningOptions, TimeInput,
};

pub(crate) fn jwks_endpoint(options: Arc<JwtOptions>) -> rustauth_core::api::AsyncAuthEndpoint {
    let path = options.jwks.jwks_path.clone();
    create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new().operation_id("getJSONWebKeySet"),
        move |context, _request| {
            let options = Arc::clone(&options);
            async move {
                if options.jwks.remote_url.is_some() {
                    return json_response(StatusCode::NOT_FOUND, &json!({"code": "NOT_FOUND"}));
                }
                let jwks = get_or_create_public_jwks(&context, &options).await?;
                json_response(StatusCode::OK, &jwks)
            }
        },
    )
}

pub(crate) fn token_endpoint(options: Arc<JwtOptions>) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/token",
        Method::GET,
        AuthEndpointOptions::new().operation_id("getJSONWebToken"),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some((session, user)) = session_user(&context, &request).await? else {
                    return json_response(
                        StatusCode::UNAUTHORIZED,
                        &json!({"code": "UNAUTHORIZED"}),
                    );
                };
                let token = sign_session_token(&context, &options, session, user).await?;
                json_response(StatusCode::OK, &json!({ "token": token }))
            }
        },
    )
}

pub(crate) fn sign_jwt_endpoint(options: Arc<JwtOptions>) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-jwt",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signJWT")
            .server_only(),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let body: SignJwtBody = parse_json(&request)?;
                let mut effective_options = options.as_ref().clone();
                if let Some(overrides) = body.override_options {
                    overrides.apply(&mut effective_options);
                    effective_options.validate()?;
                }
                let token =
                    sign::sign_jwt_with_options(&context, body.payload, &effective_options).await?;
                json_response(StatusCode::OK, &json!({ "token": token }))
            }
        },
    )
}

pub(crate) fn verify_jwt_endpoint(
    options: Arc<JwtOptions>,
) -> rustauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/verify-jwt",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("verifyJWT")
            .server_only(),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let body: VerifyJwtBody = parse_json(&request)?;
                let payload = verify::verify_jwt_with_options(
                    &context,
                    &body.token,
                    &options,
                    body.issuer.as_deref(),
                )
                .await?;
                json_response(StatusCode::OK, &json!({ "payload": payload }))
            }
        },
    )
}

async fn get_or_create_public_jwks(
    context: &AuthContext,
    options: &JwtOptions,
) -> Result<Jwks, RustAuthError> {
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
    session: rustauth_core::db::Session,
    user: rustauth_core::db::User,
) -> Result<String, RustAuthError> {
    let session_context = JwtSessionContext {
        session,
        user: user.clone(),
    };
    let mut claims = if let Some(define_payload) = &options.jwt.define_payload {
        define_payload(&session_context).await?
    } else {
        let Value::Object(map) =
            serde_json::to_value(&user).map_err(|error| RustAuthError::Api(error.to_string()))?
        else {
            return Err(RustAuthError::Api(
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
) -> Result<Option<(rustauth_core::db::Session, rustauth_core::db::User)>, RustAuthError> {
    let Some(_adapter) = context.adapter() else {
        return Ok(None);
    };
    let Some(result) = SessionAuth::new(context)?
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
    if rustauth_core::context::request_state::has_request_state() {
        set_current_session(session.clone(), user.clone())?;
        set_current_session_user(
            serde_json::to_value(&user).map_err(|error| RustAuthError::Api(error.to_string()))?,
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

fn parse_json<T>(request: &ApiRequest) -> Result<T, RustAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(request.body()).map_err(|error| RustAuthError::Api(error.to_string()))
}

fn json_response<T>(status: StatusCode, body: &T) -> Result<ApiResponse, RustAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct SignJwtBody {
    payload: JwtClaims,
    #[serde(default, rename = "overrideOptions")]
    override_options: Option<JwtEndpointOverrideOptions>,
}

#[derive(Debug, Deserialize)]
struct VerifyJwtBody {
    token: String,
    issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtEndpointOverrideOptions {
    #[serde(default)]
    jwt: Option<JwtEndpointSigningOverride>,
    #[serde(default)]
    jwks: Option<JwtEndpointJwksOverride>,
}

impl JwtEndpointOverrideOptions {
    fn apply(self, options: &mut JwtOptions) {
        if let Some(jwt) = self.jwt {
            jwt.apply(&mut options.jwt);
        }
        if let Some(jwks) = self.jwks {
            jwks.apply(&mut options.jwks);
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtEndpointSigningOverride {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    audience: Option<AudienceOverride>,
    #[serde(default, rename = "expirationTime")]
    expiration_time: Option<TimeInputOverride>,
}

impl JwtEndpointSigningOverride {
    fn apply(self, options: &mut JwtSigningOptions) {
        if let Some(issuer) = self.issuer {
            options.issuer = Some(issuer);
        }
        if let Some(audience) = self.audience {
            options.audience = Some(audience.into_vec());
        }
        if let Some(expiration_time) = self.expiration_time {
            options.expiration_time = Some(expiration_time.into_time_input());
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtEndpointJwksOverride {
    #[serde(default, rename = "remoteUrl")]
    remote_url: Option<String>,
    #[serde(default, rename = "keyPairConfig")]
    key_pair_config: Option<KeyPairConfigOverride>,
    #[serde(default, rename = "disablePrivateKeyEncryption")]
    disable_private_key_encryption: Option<bool>,
    #[serde(default, rename = "rotationInterval")]
    rotation_interval: Option<i64>,
    #[serde(default, rename = "gracePeriod")]
    grace_period: Option<i64>,
    #[serde(default, rename = "jwksPath")]
    jwks_path: Option<String>,
}

impl JwtEndpointJwksOverride {
    fn apply(self, options: &mut JwtJwksOptions) {
        if let Some(remote_url) = self.remote_url {
            options.remote_url = Some(remote_url);
        }
        if let Some(key_pair_config) = self.key_pair_config {
            if let Some(algorithm) = key_pair_config.alg {
                options.key_pair_algorithm = Some(algorithm);
            }
            if let Some(modulus_length) = key_pair_config.modulus_length {
                options.rsa_modulus_length = Some(modulus_length);
            }
        }
        if let Some(disable_private_key_encryption) = self.disable_private_key_encryption {
            options.disable_private_key_encryption = disable_private_key_encryption;
        }
        if let Some(rotation_interval) = self.rotation_interval {
            options.rotation_interval = Some(rotation_interval);
        }
        if let Some(grace_period) = self.grace_period {
            options.grace_period = grace_period;
        }
        if let Some(jwks_path) = self.jwks_path {
            options.jwks_path = jwks_path;
        }
    }
}

#[derive(Debug, Deserialize)]
struct KeyPairConfigOverride {
    #[serde(default)]
    alg: Option<JwkAlgorithm>,
    #[serde(default, rename = "modulusLength")]
    modulus_length: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceOverride {
    One(String),
    Many(Vec<String>),
}

impl AudienceOverride {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TimeInputOverride {
    Number(i64),
    String(String),
}

impl TimeInputOverride {
    fn into_time_input(self) -> TimeInput {
        match self {
            Self::Number(value) => TimeInput::UnixTimestamp(value),
            Self::String(value) => TimeInput::Duration(value),
        }
    }
}
