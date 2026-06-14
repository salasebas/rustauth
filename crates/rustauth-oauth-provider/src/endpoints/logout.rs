use super::*;

pub(super) fn logout_endpoint(options: Arc<ResolvedOAuthProviderOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/oauth2/end-session",
        Method::GET,
        AuthEndpointOptions::new(),
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let Some(adapter) = context.adapter() else {
                    return error_response(OAuthProviderError::invalid_request(
                        "database adapter required",
                    ));
                };
                let Some(id_token_hint) = query_param(&request, "id_token_hint") else {
                    return error_response(OAuthProviderError::new(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        "invalid id token",
                    ));
                };
                let validated = match validate_id_token_hint(
                    &context,
                    adapter.as_ref(),
                    &options,
                    &id_token_hint,
                    query_param(&request, "client_id").as_deref(),
                )
                .await
                {
                    Ok(validated) => validated,
                    Err(error) => return error_response(error),
                };
                adapter
                    .delete(crate::utils::delete_by_string(
                        "session",
                        "id",
                        &validated.session_id,
                    ))
                    .await?;
                if let Some(uri) = query_param(&request, "post_logout_redirect_uri") {
                    if validated
                        .client
                        .post_logout_redirect_uris
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .any(|registered| registered == &uri)
                    {
                        let mut redirect = url::Url::parse(&uri)
                            .map_err(|error| RustAuthError::Api(error.to_string()))?;
                        if let Some(state) = query_param(&request, "state") {
                            redirect.query_pairs_mut().append_pair("state", &state);
                        }
                        return redirect_response(redirect.as_str());
                    }
                }
                no_content()
            }
        },
    )
}
