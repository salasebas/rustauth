use super::*;

impl_social_oauth_provider!(
    crate::twitter::TwitterProvider,
    options | provider | { provider.provider_options().clone() },
    authorization | provider,
    input | {
        provider.create_authorization_url(crate::twitter::TwitterAuthorizationUrlRequest {
            state: input.state,
            redirect_uri: input.redirect_uri,
            code_verifier: input.code_verifier,
            scopes: input.scopes,
        })
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(crate::twitter::TwitterValidateAuthorizationCodeRequest {
                code: input.code,
                code_verifier: input.code_verifier,
                redirect_uri: input.redirect_uri,
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
