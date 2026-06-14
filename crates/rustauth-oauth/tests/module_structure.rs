use rustauth_oauth::oauth2;

#[test]
fn oauth2_module_exports_placeholder_types() {
    let provider = oauth2::OAuthProviderMetadata::new("example", "Example");

    assert_eq!(provider.id(), "example");
}

#[test]
fn social_oauth_provider_is_public() {
    fn assert_social_provider<T: oauth2::SocialOAuthProvider>() {}

    struct TestProvider;

    impl oauth2::SocialOAuthProvider for TestProvider {
        fn id(&self) -> &str {
            "test"
        }

        fn name(&self) -> &str {
            "Test"
        }

        fn provider_options(&self) -> oauth2::ProviderOptions {
            oauth2::ProviderOptions::default()
        }

        fn create_authorization_url(
            &self,
            _input: oauth2::SocialAuthorizationUrlRequest,
        ) -> Result<url::Url, oauth2::OAuthError> {
            Err(oauth2::OAuthError::InvalidConfiguration(
                "not implemented".to_owned(),
            ))
        }

        fn validate_authorization_code(
            &self,
            _input: oauth2::SocialAuthorizationCodeRequest,
        ) -> oauth2::SocialProviderFuture<'_, oauth2::OAuth2Tokens> {
            Box::pin(async {
                Err(oauth2::OAuthError::InvalidConfiguration(
                    "not implemented".to_owned(),
                ))
            })
        }

        fn get_user_info(
            &self,
            _tokens: oauth2::OAuth2Tokens,
            _provider_user: Option<serde_json::Value>,
        ) -> oauth2::SocialProviderFuture<'_, Option<oauth2::OAuth2UserInfo>> {
            Box::pin(async { Ok(None) })
        }
    }

    assert_social_provider::<TestProvider>();
}
