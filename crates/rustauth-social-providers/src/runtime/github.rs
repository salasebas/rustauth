use super::*;

impl_social_oauth_provider!(
    crate::github::GitHubProvider,
    options | provider | { provider.provider_options().clone() },
    authorization | provider,
    input | {
        provider.create_authorization_url(crate::github::GitHubAuthorizationUrlRequest {
            state: input.state,
            scopes: input.scopes,
            login_hint: input.login_hint,
            code_verifier: input.code_verifier,
            redirect_uri: input.redirect_uri,
        })
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(crate::github::GitHubValidateAuthorizationCodeRequest {
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
