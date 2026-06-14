use super::*;

impl_social_oauth_provider!(
    crate::microsoft_entra_id::MicrosoftEntraIdProvider,
    options | provider | { provider.options() },
    authorization | provider,
    input | {
        provider.create_authorization_url(
            crate::microsoft_entra_id::MicrosoftEntraIdAuthorizationUrlRequest {
                state: input.state,
                redirect_uri: input.redirect_uri,
                code_verifier: input.code_verifier,
                scopes: input.scopes,
                login_hint: input.login_hint,
            },
        )
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(
                crate::microsoft_entra_id::MicrosoftEntraIdAuthorizationCodeRequest {
                    code: input.code,
                    redirect_uri: input.redirect_uri,
                    code_verifier: input.code_verifier,
                    device_id: input.device_id,
                },
            )
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
    verify | provider,
    input | {
        provider
            .verify_id_token(&input.token, input.nonce.as_deref())
            .await
    },
    refresh | provider,
    refresh_token | { provider.refresh_access_token(refresh_token).await }
);
