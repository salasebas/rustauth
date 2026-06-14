use super::*;

impl_social_oauth_provider!(
    crate::facebook::FacebookProvider,
    options | provider | { provider.options().clone() },
    authorization | provider,
    input | {
        provider.create_authorization_url(
            input.state,
            input.scopes,
            input.redirect_uri,
            input.login_hint.as_deref(),
        )
    },
    code | provider,
    input | {
        provider
            .validate_authorization_code(input.code, input.redirect_uri)
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
        Ok(provider
            .verify_id_token(&input.token, input.nonce.as_deref())
            .await)
    },
    refresh | provider,
    refresh_token | { provider.refresh_access_token(refresh_token).await }
);
