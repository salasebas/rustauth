use super::*;

impl_social_oauth_provider!(
    crate::zoom::ZoomProvider,
    options | provider | { provider.options() },
    authorization | provider,
    input | {
        provider.create_authorization_url(crate::zoom::ZoomAuthorizationUrlRequest {
            state: input.state,
            redirect_uri: input.redirect_uri,
            code_verifier: input.code_verifier,
        })
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(crate::zoom::ZoomAuthorizationCodeRequest {
                code: input.code,
                redirect_uri: input.redirect_uri,
                code_verifier: input.code_verifier,
            })
            .await
    },
    user | provider,
    tokens,
    _provider_user | {
        provider
            .get_user_info(&tokens)
            .await
            .map(|info| info.map(|info| info.user))
    },
    verify | _provider,
    input | { unsupported_id_token(input) },
    refresh | provider,
    refresh_token | { provider.refresh_access_token(refresh_token).await }
);
