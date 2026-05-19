use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiRequest, ApiResponse, AuthEndpointOptions,
    BodyField, BodySchema, JsonSchemaType, OpenApiOperation,
};
use openauth_core::auth::oauth::{
    handle_oauth_user_info, HandleOAuthUserInfoInput, OAuthAccountInput, OAuthUserInfo,
    OAuthUserInfoError,
};
use openauth_core::context::request_state::{has_request_state, set_current_new_session};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuth2UserInfo, ProviderOptions, SocialIdTokenRequest,
    SocialOAuthProvider,
};
use openauth_social_providers::google::{google, GoogleOptions};
use serde::Deserialize;
use serde_json::json;

use super::options::OneTapOptions;
use super::response::{error_response, session_response};

const GOOGLE_PROVIDER_ID: &str = "google";
const GOOGLE_SCOPE: &str = "openid,profile,email";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OneTapCallbackBody {
    id_token: String,
}

pub(super) fn one_tap_callback_endpoint(
    options: OneTapOptions,
) -> openauth_core::api::AsyncAuthEndpoint {
    create_auth_endpoint(
        "/one-tap/callback",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("oneTapCallback")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(one_tap_callback_body_schema())
            .openapi(
                OpenApiOperation::new("oneTapCallback")
                    .description("Authenticate with Google One Tap")
                    .response(
                        "200",
                        json!({
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "token": { "type": "string" },
                                            "user": { "$ref": "#/components/schemas/User" }
                                        }
                                    }
                                }
                            }
                        }),
                    )
                    .response(
                        "400",
                        json!({
                            "description": "Invalid token",
                        }),
                    ),
            ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move { handle_one_tap_callback(context, request, options).await })
        },
    )
}

async fn handle_one_tap_callback(
    context: &AuthContext,
    request: ApiRequest,
    options: OneTapOptions,
) -> Result<ApiResponse, OpenAuthError> {
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig(
            "one-tap callback requires an adapter-backed OpenAuth instance".to_owned(),
        )
    })?;
    let body: OneTapCallbackBody = parse_request_body(&request)?;
    let provider = google_provider(context, &options)?;
    let tokens = OAuth2Tokens {
        id_token: Some(body.id_token.clone()),
        scopes: google_scopes(),
        ..OAuth2Tokens::default()
    };

    if !provider
        .verify_id_token(SocialIdTokenRequest {
            token: body.id_token.clone(),
            ..SocialIdTokenRequest::default()
        })
        .await?
    {
        return error_response(StatusCode::BAD_REQUEST, "INVALID_TOKEN", "invalid id token");
    }

    let Some(user_info) = provider.get_user_info(tokens.clone(), None).await? else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "EMAIL_NOT_AVAILABLE",
            "Email not available in token",
        );
    };
    let Some(normalized) = normalize_user_info(&user_info) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "EMAIL_NOT_AVAILABLE",
            "Email not available in token",
        );
    };
    let result = handle_oauth_user_info(
        context,
        adapter.as_ref(),
        HandleOAuthUserInfoInput {
            account: oauth_account(&user_info, &tokens),
            user_info: normalized,
            disable_sign_up: options.disable_signup,
            override_user_info: provider.provider_options().override_user_info_on_sign_in,
            is_trusted_provider: true,
            ..HandleOAuthUserInfoInput::default()
        },
    )
    .await?;

    let Some(data) = result.data else {
        let error = result
            .error
            .unwrap_or(OAuthUserInfoError::UnableToCreateUser);
        return oauth_error_response(error);
    };

    if has_request_state() {
        set_current_new_session(data.session.clone(), data.user.clone())?;
    }

    session_response(
        context,
        adapter.as_ref(),
        data.session,
        data.user,
        result.cookies,
    )
    .await
}

fn google_provider(
    context: &AuthContext,
    options: &OneTapOptions,
) -> Result<Arc<dyn SocialOAuthProvider>, OpenAuthError> {
    if let Some(client_id) = options.client_id.as_ref().filter(|value| !value.is_empty()) {
        let provider_options = context
            .social_provider(GOOGLE_PROVIDER_ID)
            .map(|provider| provider.provider_options())
            .unwrap_or_default();
        return Ok(Arc::new(google(GoogleOptions {
            oauth: ProviderOptions {
                client_id: Some(ClientId::Single(client_id.clone())),
                ..provider_options
            },
            ..GoogleOptions::default()
        })));
    }

    context.social_provider(GOOGLE_PROVIDER_ID).ok_or_else(|| {
        OpenAuthError::InvalidConfig("one-tap requires a configured google provider".to_owned())
    })
}

fn normalize_user_info(info: &OAuth2UserInfo) -> Option<OAuthUserInfo> {
    let email = info.email.clone()?;
    Some(OAuthUserInfo {
        id: info.id.clone(),
        name: info.name.clone().unwrap_or_default(),
        email,
        image: info.image.clone(),
        email_verified: info.email_verified,
        raw_attributes: None,
    })
}

fn oauth_account(info: &OAuth2UserInfo, tokens: &OAuth2Tokens) -> OAuthAccountInput {
    OAuthAccountInput {
        provider_id: GOOGLE_PROVIDER_ID.to_owned(),
        account_id: info.id.clone(),
        id_token: tokens.id_token.clone(),
        scope: Some(GOOGLE_SCOPE.to_owned()),
        ..OAuthAccountInput::default()
    }
}

fn oauth_error_response(error: OAuthUserInfoError) -> Result<ApiResponse, OpenAuthError> {
    match error {
        OAuthUserInfoError::SignupDisabled => {
            error_response(StatusCode::BAD_GATEWAY, "SIGNUP_DISABLED", "User not found")
        }
        OAuthUserInfoError::AccountNotLinked => error_response(
            StatusCode::UNAUTHORIZED,
            "ACCOUNT_NOT_LINKED",
            "Google sub doesn't match",
        ),
        OAuthUserInfoError::UnableToCreateUser => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNABLE_TO_CREATE_USER",
            "Could not create user",
        ),
        OAuthUserInfoError::UnableToCreateSession => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNABLE_TO_CREATE_SESSION",
            "Could not create session",
        ),
        OAuthUserInfoError::UnableToLinkAccount => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNABLE_TO_LINK_ACCOUNT",
            "Could not link account",
        ),
    }
}

fn one_tap_callback_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("idToken", JsonSchemaType::String)
        .description("Google ID token, which the client obtains from the One Tap API")])
}

fn google_scopes() -> Vec<String> {
    ["openid", "profile", "email"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}
