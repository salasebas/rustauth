use std::sync::Arc;

use http::{header, HeaderValue, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions,
    BodyField, BodySchema, JsonSchemaType,
};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{set_session_cookie, Cookie, CookieOptions, SessionCookieOptions};
use openauth_core::db::{DbAdapter, User};
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateOAuthAccountInput, CreateUserInput, DbUserStore};
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

use super::address::checksum_address;
use super::store;
use super::types::{
    Cacao, CacaoHeader, CacaoPayload, CacaoSignature, EnsLookupArgs, NonceRequest, SiweOptions,
    SiweVerifyMessageArgs, VerifyRequest,
};

const NONCE_TTL_MINUTES: i64 = 15;

pub(crate) fn nonce_endpoint(options: SiweOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/siwe/nonce",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("getSiweNonce")
            .body_schema(nonce_body_schema()),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ADAPTER_REQUIRED",
                        "SIWE requires an adapter-backed OpenAuth instance",
                    );
                };
                let body: NonceRequest = parse_request_body(&request)?;
                let Ok(wallet_address) = checksum_address(&body.wallet_address) else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "INVALID_WALLET_ADDRESS",
                        "Invalid wallet address",
                    );
                };
                if body.chain_id <= 0 {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "INVALID_CHAIN_ID",
                        "chainId must be positive",
                    );
                }

                let nonce = (options.get_nonce)().await?;
                DbVerificationStore::new(adapter.as_ref())
                    .create_verification(CreateVerificationInput::new(
                        verification_identifier(&wallet_address, body.chain_id),
                        nonce.clone(),
                        OffsetDateTime::now_utc() + Duration::minutes(NONCE_TTL_MINUTES),
                    ))
                    .await?;
                json_response(StatusCode::OK, &NonceResponse { nonce }, Vec::new())
            })
        },
    )
}

pub(crate) fn verify_endpoint(options: SiweOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/siwe/verify",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("verifySiweMessage")
            .body_schema(verify_body_schema()),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ADAPTER_REQUIRED",
                        "SIWE requires an adapter-backed OpenAuth instance",
                    );
                };
                let body: VerifyRequest = parse_request_body(&request)?;
                verify_request(context, adapter, &options, body).await
            })
        },
    )
}

async fn verify_request(
    context: &AuthContext,
    adapter: Arc<dyn DbAdapter>,
    options: &SiweOptions,
    body: VerifyRequest,
) -> Result<ApiResponse, OpenAuthError> {
    if body.message.is_empty() || body.signature.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST_BODY",
            "message and signature are required",
        );
    }
    if body.chain_id <= 0 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_CHAIN_ID",
            "chainId must be positive",
        );
    }
    if !options.anonymous && !body.email.as_deref().is_some_and(is_valid_email) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "EMAIL_REQUIRED",
            "Email is required when anonymous is disabled.",
        );
    }
    if body
        .email
        .as_deref()
        .is_some_and(|email| !is_valid_email(email))
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_EMAIL",
            "Invalid email address",
        );
    }

    let Ok(wallet_address) = checksum_address(&body.wallet_address) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_WALLET_ADDRESS",
            "Invalid wallet address",
        );
    };
    let identifier = verification_identifier(&wallet_address, body.chain_id);
    let verification_store = DbVerificationStore::new(adapter.as_ref());
    let Some(verification) = verification_store.find_verification(&identifier).await? else {
        return invalid_nonce();
    };

    let verified = (options.verify_message)(SiweVerifyMessageArgs {
        message: body.message.clone(),
        signature: body.signature.clone(),
        address: wallet_address.clone(),
        chain_id: body.chain_id,
        cacao: cacao(options, &verification.value, &body.signature),
    })
    .await?;
    if !verified {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Unauthorized: Invalid SIWE signature",
        );
    }

    verification_store.delete_verification(&identifier).await?;
    let user =
        find_or_create_user(context, adapter.as_ref(), options, &body, &wallet_address).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            user.id.clone(),
            OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64),
        ))
        .await?;
    let cookies = session_cookies(context, &session.token)?;

    json_response(
        StatusCode::OK,
        &VerifyResponse {
            token: session.token,
            success: true,
            user: VerifyUserResponse {
                id: user.id,
                wallet_address,
                chain_id: body.chain_id,
            },
        },
        cookies,
    )
}

async fn find_or_create_user(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    options: &SiweOptions,
    body: &VerifyRequest,
    wallet_address: &str,
) -> Result<User, OpenAuthError> {
    let users = DbUserStore::new(adapter);
    let existing_wallet = store::find_wallet(adapter, wallet_address, body.chain_id).await?;
    if let Some(wallet) = &existing_wallet {
        if let Some(user) = store::user_for_wallet(adapter, wallet).await? {
            return Ok(user);
        }
    }

    if let Some(wallet) = store::find_wallet_by_address(adapter, wallet_address).await? {
        if let Some(user) = store::user_for_wallet(adapter, &wallet).await? {
            store::create_wallet(adapter, &user.id, wallet_address, body.chain_id, false).await?;
            users
                .link_account(CreateOAuthAccountInput {
                    id: None,
                    provider_id: "siwe".to_owned(),
                    account_id: format!("{wallet_address}:{}", body.chain_id),
                    user_id: user.id.clone(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?;
            return Ok(user);
        }
    }

    let ens = match &options.ens_lookup {
        Some(lookup) => {
            (lookup)(EnsLookupArgs {
                wallet_address: wallet_address.to_owned(),
            })
            .await?
        }
        None => None,
    };
    let email = if options.anonymous {
        format!(
            "{wallet_address}@{}",
            options
                .email_domain_name
                .as_deref()
                .unwrap_or_else(|| email_domain(context))
        )
    } else {
        body.email.clone().unwrap_or_default()
    };
    let mut create_user = CreateUserInput::new(
        ens.as_ref()
            .map(|result| result.name.clone())
            .unwrap_or_else(|| wallet_address.to_owned()),
        email,
    );
    if let Some(avatar) = ens
        .map(|result| result.avatar)
        .filter(|avatar| !avatar.is_empty())
    {
        create_user = create_user.image(avatar);
    }
    let user = users.create_user(create_user).await?;
    store::create_wallet(adapter, &user.id, wallet_address, body.chain_id, true).await?;
    users
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: "siwe".to_owned(),
            account_id: format!("{wallet_address}:{}", body.chain_id),
            user_id: user.id.clone(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await?;
    Ok(user)
}

fn nonce_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("walletAddress", JsonSchemaType::String),
        BodyField::optional("chainId", JsonSchemaType::Number),
    ])
}

fn verify_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("message", JsonSchemaType::String),
        BodyField::new("signature", JsonSchemaType::String),
        BodyField::new("walletAddress", JsonSchemaType::String),
        BodyField::optional("chainId", JsonSchemaType::Number),
        BodyField::optional("email", JsonSchemaType::String).format("email"),
    ])
}

fn verification_identifier(wallet_address: &str, chain_id: i64) -> String {
    format!("siwe:{wallet_address}:{chain_id}")
}

fn cacao(options: &SiweOptions, nonce: &str, signature: &str) -> Cacao {
    Cacao {
        h: CacaoHeader {
            t: "caip122".to_owned(),
        },
        p: CacaoPayload {
            domain: options.domain.clone(),
            aud: options.domain.clone(),
            nonce: nonce.to_owned(),
            iss: options.domain.clone(),
            version: Some("1".to_owned()),
            iat: None,
            nbf: None,
            exp: None,
            statement: None,
            request_id: None,
            resources: None,
            r#type: None,
        },
        s: CacaoSignature {
            t: "eip191".to_owned(),
            s: signature.to_owned(),
            m: None,
        },
    }
}

fn invalid_nonce() -> Result<ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
        "Unauthorized: Invalid or expired nonce",
    )
}

fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
}

fn email_domain(context: &AuthContext) -> &str {
    context
        .base_url
        .strip_prefix("https://")
        .or_else(|| context.base_url.strip_prefix("http://"))
        .and_then(|value| value.split('/').next())
        .filter(|value| !value.is_empty())
        .unwrap_or("localhost")
}

fn session_cookies(context: &AuthContext, token: &str) -> Result<Vec<Cookie>, OpenAuthError> {
    set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions {
            dont_remember: false,
            overrides: CookieOptions::default(),
        },
    )
}

fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut parts = vec![format!("{}={}", cookie.name, cookie.value)];
    if let Some(max_age) = cookie.attributes.max_age {
        parts.push(format!("Max-Age={max_age}"));
    }
    if let Some(expires) = &cookie.attributes.expires {
        parts.push(format!("Expires={expires}"));
    }
    if let Some(domain) = &cookie.attributes.domain {
        parts.push(format!("Domain={domain}"));
    }
    if let Some(path) = &cookie.attributes.path {
        parts.push(format!("Path={path}"));
    }
    if cookie.attributes.secure.unwrap_or(false) {
        parts.push("Secure".to_owned());
    }
    if cookie.attributes.http_only.unwrap_or(false) {
        parts.push("HttpOnly".to_owned());
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        parts.push(format!("SameSite={same_site}"));
    }
    if cookie.attributes.partitioned.unwrap_or(false) {
        parts.push("Partitioned".to_owned());
    }
    parts.join("; ")
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ErrorResponse {
            code: code.to_owned(),
            message: message.to_owned(),
        },
        Vec::new(),
    )
}

#[derive(Serialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct NonceResponse {
    nonce: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    token: String,
    success: bool,
    user: VerifyUserResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyUserResponse {
    id: String,
    wallet_address: String,
    chain_id: i64,
}
