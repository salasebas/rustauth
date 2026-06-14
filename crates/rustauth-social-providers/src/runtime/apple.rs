use super::*;

impl_social_oauth_provider!(
    crate::apple::AppleProvider,
    options | provider | { provider.options().oauth.clone() },
    authorization | provider,
    input | { provider.create_authorization_url(&input.state, input.scopes, &input.redirect_uri) },
    code | provider,
    input | {
        provider
            .validate_authorization_code(input.code, input.code_verifier, input.redirect_uri)
            .await
    },
    user | provider,
    tokens,
    provider_user | {
        let apple_user = parse_provider_user::<crate::apple::AppleNonConformUser>(provider_user)?;
        provider
            .get_user_info(&tokens, apple_user)
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
