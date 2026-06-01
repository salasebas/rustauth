mod flow;
mod support;

use http::Method;
use serde_json::Value;
use std::sync::Arc;

use super::shared::{sensitive_session, unauthorized};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use crate::auth::oauth::{generate_oauth_state, OAuthStateInput, OAuthStateLink};
use crate::db::DbAdapter;
use openauth_oauth::oauth2::SocialAuthorizationUrlRequest;

use flow::{
    callback_get, callback_post_redirect, link_with_id_token, lookup_provider,
    sign_in_with_id_token,
};
use support::{
    link_social_body_schema, redirect_json_response, redirect_uri, social_sign_in_body_schema,
    LinkSocialBody, SocialSignInBody,
};

pub(super) fn sign_in_social_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    sign_in_oauth_endpoint(
        "/sign-in/social",
        "socialSignIn",
        "Sign in with a social provider",
        adapter,
    )
}

pub(super) fn sign_in_oauth2_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    sign_in_oauth_endpoint(
        "/sign-in/oauth2",
        "oauth2SignIn",
        "Sign in with an OAuth2 provider",
        adapter,
    )
}

fn sign_in_oauth_endpoint(
    path: &'static str,
    operation_id: &'static str,
    description: &'static str,
    adapter: Arc<dyn DbAdapter>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id(operation_id)
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(social_sign_in_body_schema())
            .openapi(OpenApiOperation::new(operation_id).description(description)),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let body: SocialSignInBody = parse_request_body(&request)?;
                let provider = lookup_provider(context, &body.provider)?;
                if let Some(id_token) = body.id_token {
                    return sign_in_with_id_token(context, adapter.as_ref(), provider, id_token)
                        .await;
                }
                let state = generate_oauth_state(
                    context,
                    Some(adapter.as_ref()),
                    OAuthStateInput {
                        callback_url: body.callback_url.unwrap_or_else(|| "/".to_owned()),
                        error_url: body.error_callback_url,
                        new_user_url: body.new_user_callback_url,
                        request_sign_up: body.request_sign_up,
                        additional_data: body.additional_data.unwrap_or(Value::Null),
                        ..OAuthStateInput::default()
                    },
                )
                .await?;
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri: redirect_uri(context, &request, provider.id()),
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: body.login_hint,
                })?;
                redirect_json_response(url.to_string(), !body.disable_redirect)
            })
        },
    )
}

pub(super) fn callback_oauth_endpoint(
    method: Method,
    adapter: Arc<dyn DbAdapter>,
) -> AsyncAuthEndpoint {
    let mut options = AuthEndpointOptions::new()
        .operation_id("handleOAuthCallback")
        .openapi(OpenApiOperation::new("handleOAuthCallback").description("Handle OAuth callback"));
    // Providers using OAuth `response_mode=form_post` (e.g. Apple) deliver the
    // authorization response as a cross-site POST navigation, which the origin
    // security layer otherwise blocks as `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`.
    // Only the POST callback bypasses that check so `callback_post_redirect` can
    // reflect the form into the GET callback, where the signed OAuth `state` is
    // still validated. The GET callback and other sign-in/link POST endpoints
    // remain protected.
    if method == Method::POST {
        options = options.bypass_origin_security();
    }
    create_auth_endpoint("/callback/:id", method, options, move |context, request| {
        let adapter = Arc::clone(&adapter);
        Box::pin(async move {
            if request.method() == Method::POST {
                return callback_post_redirect(context, &request);
            }
            callback_get(context, adapter.as_ref(), request).await
        })
    })
}

pub(super) fn link_social_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/link-social",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("linkSocialAccount")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(link_social_body_schema())
            .openapi(
                OpenApiOperation::new("linkSocialAccount").description("Link a social account"),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_session, user, _cookies)) =
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: LinkSocialBody = parse_request_body(&request)?;
                let provider = lookup_provider(context, &body.provider)?;
                if let Some(id_token) = body.id_token {
                    return link_with_id_token(
                        context,
                        adapter.as_ref(),
                        provider,
                        &user,
                        id_token,
                    )
                    .await;
                }
                let state = generate_oauth_state(
                    context,
                    Some(adapter.as_ref()),
                    OAuthStateInput {
                        callback_url: body.callback_url.unwrap_or_else(|| "/".to_owned()),
                        error_url: body.error_callback_url,
                        link: Some(OAuthStateLink {
                            user_id: user.id,
                            email: user.email,
                        }),
                        request_sign_up: body.request_sign_up,
                        additional_data: body.additional_data.unwrap_or(Value::Null),
                        ..OAuthStateInput::default()
                    },
                )
                .await?;
                let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
                    state: state.state,
                    redirect_uri: redirect_uri(context, &request, provider.id()),
                    code_verifier: Some(state.data.code_verifier),
                    scopes: body.scopes,
                    login_hint: None,
                })?;
                redirect_json_response(url.to_string(), !body.disable_redirect)
            })
        },
    )
}
