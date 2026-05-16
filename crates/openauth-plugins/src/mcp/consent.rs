use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType,
};
use openauth_core::db::{Create, DbValue, Delete, FindOne, Update, Where};
use serde::Deserialize;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use super::shared::{
    adapter, current_session, expire_prompt_cookie, json_response, oauth_error, optional_timestamp,
    random_token, redirect_error_url, request_cookie, required_string, verify_signed_cookie,
    CONSENT_PROMPT_COOKIE,
};
use super::ResolvedMcpOptions;

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    accept: bool,
    consent_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerificationCodeValue {
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "redirectURI")]
    redirect_uri: String,
    scope: Vec<String>,
    #[serde(rename = "userId")]
    user_id: String,
    state: Option<String>,
    #[serde(rename = "requireConsent")]
    require_consent: Option<bool>,
    #[serde(rename = "codeChallenge")]
    code_challenge: Option<String>,
    #[serde(rename = "codeChallengeMethod")]
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    #[serde(rename = "authTime")]
    auth_time: Option<i64>,
}

pub fn consent_endpoint(options: ResolvedMcpOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/consent",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("mcpOAuthConsent")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(BodySchema::object([
                BodyField::new("accept", JsonSchemaType::Boolean),
                BodyField::optional("consent_code", JsonSchemaType::String),
            ])),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = adapter(context)?;
                let Some(session) = current_session(adapter.as_ref(), context, &request).await?
                else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_request",
                        "session is required",
                    );
                };
                let body: Value = parse_request_body(&request)?;
                let body: ConsentRequest = serde_json::from_value(body)
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
                let consent_code = match body.consent_code {
                    Some(code) => code,
                    None => {
                        let Some(cookie) = request_cookie(&request, CONSENT_PROMPT_COOKIE) else {
                            return oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                "consent_code is required",
                            );
                        };
                        let Some(code) = verify_signed_cookie(&cookie, &context.secret)? else {
                            return oauth_error(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                "invalid consent cookie",
                            );
                        };
                        code
                    }
                };
                let Some(record) = adapter
                    .find_one(FindOne::new("verification").where_clause(Where::new(
                        "identifier",
                        DbValue::String(consent_code.clone()),
                    )))
                    .await?
                else {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_request",
                        "Invalid code",
                    );
                };
                if optional_timestamp(&record, "expires_at")?
                    .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
                {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_request",
                        "Code expired",
                    );
                }
                let value: VerificationCodeValue =
                    serde_json::from_str(&required_string(&record, "value")?).map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(error.to_string())
                    })?;
                if session.user_id != value.user_id {
                    return oauth_error(
                        StatusCode::FORBIDDEN,
                        "access_denied",
                        "consent session does not match authorization request",
                    );
                }
                if value.require_consent != Some(true) {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_request",
                        "Consent not required",
                    );
                }
                if !body.accept {
                    adapter
                        .delete(
                            Delete::new("verification").where_clause(Where::new(
                                "identifier",
                                DbValue::String(consent_code),
                            )),
                        )
                        .await?;
                    let mut response = json_response(
                        StatusCode::OK,
                        &json!({
                            "redirectURI": redirect_error_url(
                                &value.redirect_uri,
                                "access_denied",
                                "User denied access"
                            )
                        }),
                    )?;
                    expire_prompt_cookie(&mut response, CONSENT_PROMPT_COOKIE)?;
                    return Ok(response);
                }

                let now = OffsetDateTime::now_utc();
                let code = random_token();
                let verification_value = json!({
                    "clientId": value.client_id,
                    "redirectURI": value.redirect_uri,
                    "scope": value.scope,
                    "userId": value.user_id,
                    "authTime": value.auth_time,
                    "requireConsent": false,
                    "state": value.state,
                    "codeChallenge": value.code_challenge,
                    "codeChallengeMethod": value.code_challenge_method,
                    "nonce": value.nonce,
                });
                adapter
                    .update(
                        Update::new("verification")
                            .where_clause(Where::new(
                                "identifier",
                                DbValue::String(consent_code.clone()),
                            ))
                            .data("identifier", DbValue::String(code.clone()))
                            .data("value", DbValue::String(verification_value.to_string()))
                            .data(
                                "expires_at",
                                DbValue::Timestamp(
                                    now + Duration::seconds(options.code_expires_in as i64),
                                ),
                            )
                            .data("updated_at", DbValue::Timestamp(now)),
                    )
                    .await?;
                adapter
                    .create(
                        Create::new("oauthConsent")
                            .data("clientId", DbValue::String(value.client_id.clone()))
                            .data("userId", DbValue::String(value.user_id.clone()))
                            .data("scopes", DbValue::String(value.scope.join(" ")))
                            .data("createdAt", DbValue::Timestamp(now))
                            .data("updatedAt", DbValue::Timestamp(now))
                            .data("consentGiven", DbValue::Boolean(true)),
                    )
                    .await?;
                let mut redirect_uri = url::Url::parse(&value.redirect_uri)
                    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
                redirect_uri.query_pairs_mut().append_pair("code", &code);
                if let Some(state) = value.state {
                    redirect_uri.query_pairs_mut().append_pair("state", &state);
                }
                let mut response = json_response(
                    StatusCode::OK,
                    &json!({ "redirectURI": redirect_uri.to_string() }),
                )?;
                expire_prompt_cookie(&mut response, CONSENT_PROMPT_COOKIE)?;
                Ok(response)
            })
        },
    )
}
