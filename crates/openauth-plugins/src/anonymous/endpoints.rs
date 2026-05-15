use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::error::OpenAuthError;
use serde::Serialize;

use super::cookies::session_cookies;
use super::errors::{error_response, AnonymousError};
use super::fields::{anonymous_session_create_values, anonymous_user_create_values};
use super::model;
use super::options::AnonymousOptions;
use super::response::{delete_response, json_response, message_response, sign_in_response};

const DEFAULT_ID_LENGTH: usize = 32;

#[derive(Debug, Serialize)]
struct SignInAnonymousBody {
    token: String,
    user: model::AnonymousUser,
}

#[derive(Debug, Serialize)]
struct DeleteAnonymousUserBody {
    success: bool,
}

pub fn sign_in_anonymous_endpoint(options: AnonymousOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/anonymous",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInAnonymous")
            .openapi(
                OpenApiOperation::new("signInAnonymous")
                    .description("Sign in anonymously")
                    .response("200", sign_in_response()),
            ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move { sign_in_anonymous(context, request, options).await })
        },
    )
}

pub fn delete_anonymous_user_endpoint(options: AnonymousOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/delete-anonymous-user",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("deleteAnonymousUser")
            .openapi(
                OpenApiOperation::new("deleteAnonymousUser")
                    .description("Delete an anonymous user")
                    .response("200", delete_response())
                    .response(
                        "400",
                        message_response("Anonymous user deletion is disabled"),
                    )
                    .response("500", message_response("Internal server error")),
            ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move { delete_anonymous_user(context, request, options).await })
        },
    )
}

async fn sign_in_anonymous(
    context: &AuthContext,
    request: ApiRequest,
    options: AnonymousOptions,
) -> Result<ApiResponse, OpenAuthError> {
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::Adapter("anonymous plugin requires a database adapter".to_owned())
    })?;
    let cookie_header = cookie_header(&request);
    if model::current_anonymous_session(
        adapter.as_ref(),
        context,
        options.storage_field_name(),
        cookie_header,
    )
    .await?
    .is_some_and(|session| session.user.is_anonymous)
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            AnonymousError::AnonymousUsersCannotSignInAgainAnonymously,
        );
    }

    let email = match anonymous_email(&options).await {
        Ok(email) => email,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    let name = match options.generate_name.as_ref() {
        Some(generate) => generate().await,
        None => "Anonymous".to_owned(),
    };
    let user = match model::create_anonymous_user(
        adapter.as_ref(),
        options.storage_field_name(),
        anonymous_user_create_values(context, options.storage_field_name())?,
        generate_random_string(DEFAULT_ID_LENGTH),
        name,
        email,
    )
    .await
    {
        Ok(user) => user,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                AnonymousError::FailedToCreateUser,
            );
        }
    };
    let session = match model::create_session(
        adapter.as_ref(),
        context,
        &user.id,
        anonymous_session_create_values(context),
    )
    .await
    {
        Ok(session) => session,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                AnonymousError::CouldNotCreateSession,
            );
        }
    };
    let cookies = session_cookies(context, &session, &user)?;

    json_response(
        StatusCode::OK,
        &SignInAnonymousBody {
            token: session.token,
            user,
        },
        cookies,
    )
}

async fn delete_anonymous_user(
    context: &AuthContext,
    request: ApiRequest,
    options: AnonymousOptions,
) -> Result<ApiResponse, OpenAuthError> {
    if options.disable_delete_anonymous_user {
        return error_response(
            StatusCode::BAD_REQUEST,
            AnonymousError::DeleteAnonymousUserDisabled,
        );
    }
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::Adapter("anonymous plugin requires a database adapter".to_owned())
    })?;
    let cookie_header = cookie_header(&request);
    let Some(session) = model::current_anonymous_session(
        adapter.as_ref(),
        context,
        options.storage_field_name(),
        cookie_header.clone(),
    )
    .await?
    else {
        return error_response(StatusCode::FORBIDDEN, AnonymousError::UserIsNotAnonymous);
    };
    if !session.user.is_anonymous {
        return error_response(StatusCode::FORBIDDEN, AnonymousError::UserIsNotAnonymous);
    }
    if model::delete_anonymous_user_records(adapter.as_ref(), &session.user.id)
        .await
        .is_err()
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            AnonymousError::FailedToDeleteAnonymousUser,
        );
    }

    json_response(
        StatusCode::OK,
        &DeleteAnonymousUserBody { success: true },
        model::delete_session_cookies(context, &cookie_header),
    )
}

async fn anonymous_email(options: &AnonymousOptions) -> Result<String, AnonymousError> {
    if let Some(generate) = &options.generate_random_email {
        let email = generate().await;
        if !valid_email(&email) {
            return Err(AnonymousError::InvalidEmailFormat);
        }
        return Ok(email);
    }
    let id = generate_random_string(DEFAULT_ID_LENGTH);
    if let Some(domain) = &options.email_domain_name {
        return Ok(format!("temp-{id}@{domain}"));
    }
    Ok(format!("temp@{id}.com"))
}

fn valid_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.contains('.')
}

fn cookie_header(request: &ApiRequest) -> String {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}
