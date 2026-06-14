use super::*;

impl_social_oauth_provider!(
    crate::linear::LinearProvider,
    options | provider | { provider.options() },
    authorization | provider,
    input | {
        provider.create_authorization_url(crate::linear::LinearAuthorizationUrlRequest {
            state: input.state,
            redirect_uri: input.redirect_uri,
            scopes: input.scopes,
            login_hint: input.login_hint,
        })
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(crate::linear::LinearValidateAuthorizationCodeRequest {
                code: input.code,
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
