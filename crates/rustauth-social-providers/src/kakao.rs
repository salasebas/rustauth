//! Kakao social OAuth provider.

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

pub const KAKAO_ID: &str = "kakao";
pub const KAKAO_NAME: &str = "Kakao";
pub const KAKAO_AUTHORIZATION_ENDPOINT: &str = "https://kauth.kakao.com/oauth/authorize";
pub const KAKAO_TOKEN_ENDPOINT: &str = "https://kauth.kakao.com/oauth/token";
pub const KAKAO_USER_INFO_ENDPOINT: &str = "https://kapi.kakao.com/v2/user/me";

const DEFAULT_SCOPES: &[&str] = &["account_email", "profile_image", "profile_nickname"];

/// Kakao provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KakaoProviderOptions {
    pub oauth: ProviderOptions,
}

/// Input used to create a Kakao authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KakaoAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

/// Kakao partner payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KakaoPartner {
    pub uuid: Option<String>,
}

/// Kakao account profile payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KakaoAccountProfile {
    pub nickname: Option<String>,
    pub thumbnail_image_url: Option<String>,
    pub profile_image_url: Option<String>,
    pub is_default_image: Option<bool>,
    pub is_default_nickname: Option<bool>,
}

/// Kakao account payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KakaoAccount {
    pub profile_needs_agreement: Option<bool>,
    pub profile_nickname_needs_agreement: Option<bool>,
    pub profile_image_needs_agreement: Option<bool>,
    pub profile: Option<KakaoAccountProfile>,
    pub name_needs_agreement: Option<bool>,
    pub name: Option<String>,
    pub email_needs_agreement: Option<bool>,
    pub is_email_valid: Option<bool>,
    pub is_email_verified: Option<bool>,
    pub email: Option<String>,
    pub age_range_needs_agreement: Option<bool>,
    pub age_range: Option<String>,
    pub birthyear_needs_agreement: Option<bool>,
    pub birthyear: Option<String>,
    pub birthday_needs_agreement: Option<bool>,
    pub birthday: Option<String>,
    pub birthday_type: Option<String>,
    pub is_leap_month: Option<bool>,
    pub gender_needs_agreement: Option<bool>,
    pub gender: Option<String>,
    pub phone_number_needs_agreement: Option<bool>,
    pub phone_number: Option<String>,
    pub ci_needs_agreement: Option<bool>,
    pub ci: Option<String>,
    pub ci_authenticated_at: Option<String>,
}

/// Kakao user profile returned by `/v2/user/me`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KakaoProfile {
    pub id: u64,
    pub has_signed_up: Option<bool>,
    pub connected_at: Option<String>,
    pub synched_at: Option<String>,
    #[serde(default)]
    pub properties: std::collections::BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub kakao_account: KakaoAccount,
    pub for_partner: Option<KakaoPartner>,
}

/// User info plus raw Kakao profile data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KakaoUserInfo {
    pub user: OAuth2UserInfo,
    pub data: KakaoProfile,
}

/// Kakao OAuth provider.
#[derive(Debug, Clone)]
pub struct KakaoProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn kakao(oauth: ProviderOptions) -> Result<KakaoProvider, OAuthError> {
    KakaoProvider::new(KakaoProviderOptions { oauth })
}

impl KakaoProvider {
    #[deprecated(note = "use advanced::kakao::kakao() instead")]
    pub fn new(options: KakaoProviderOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(KAKAO_ID, options.oauth)
            .authorization_endpoint(KAKAO_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(KAKAO_TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn token_endpoint(&self) -> &str {
        KAKAO_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        KAKAO_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: KakaoAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?;
        if let Some(code_verifier) = request.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        url.scopes(request.scopes).build()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token)?.send().await
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<KakaoUserInfo>, OAuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(KAKAO_USER_INFO_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        let profile = match response.json::<KakaoProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::map_profile(profile)))
    }

    pub fn map_profile(profile: KakaoProfile) -> KakaoUserInfo {
        let user = Self::map_profile_to_user_info(&profile);
        KakaoUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_profile_to_user_info(profile: &KakaoProfile) -> OAuth2UserInfo {
        let account = &profile.kakao_account;
        let kakao_profile = account.profile.as_ref();
        let name = kakao_profile
            .and_then(|profile| profile.nickname.clone())
            .or_else(|| account.name.clone())
            .unwrap_or_default();
        let image = kakao_profile.and_then(|profile| {
            profile
                .profile_image_url
                .clone()
                .or_else(|| profile.thumbnail_image_url.clone())
        });

        OAuth2UserInfo {
            id: profile.id.to_string(),
            name: Some(name),
            email: account.email.clone(),
            image,
            email_verified: account.is_email_valid.unwrap_or(false)
                && account.is_email_verified.unwrap_or(false),
        }
    }
}

impl ProviderIdentity for KakaoProvider {
    fn id(&self) -> &str {
        KAKAO_ID
    }

    fn name(&self) -> &str {
        KAKAO_NAME
    }
}
