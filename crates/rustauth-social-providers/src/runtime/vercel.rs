use super::*;

impl_social_oauth_provider!(
    crate::vercel::VercelProvider,
    options | provider | { provider.options() },
    authorization | provider,
    input | {
        provider.create_authorization_url(crate::vercel::VercelAuthorizationUrlRequest {
            state: input.state,
            redirect_uri: input.redirect_uri,
            code_verifier: input.code_verifier,
            scopes: input.scopes,
        })
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(input.code, input.code_verifier, input.redirect_uri)
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
    refresh | _provider,
    refresh_token | {
        Err(OAuthError::InvalidResponse(format!(
            "provider does not support refresh tokens for token `{refresh_token}`"
        )))
    }
);
