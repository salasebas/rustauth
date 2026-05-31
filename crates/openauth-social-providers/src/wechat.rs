//! WeChat social OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    get_primary_client_id, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract,
    ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use url::Url;

pub const WECHAT_ID: &str = "wechat";
pub const WECHAT_NAME: &str = "WeChat";
pub const WECHAT_AUTHORIZATION_ENDPOINT: &str = "https://open.weixin.qq.com/connect/qrconnect";
pub const WECHAT_TOKEN_ENDPOINT: &str = "https://api.weixin.qq.com/sns/oauth2/access_token";
pub const WECHAT_REFRESH_TOKEN_ENDPOINT: &str =
    "https://api.weixin.qq.com/sns/oauth2/refresh_token";
pub const WECHAT_USER_INFO_ENDPOINT: &str = "https://api.weixin.qq.com/sns/userinfo";

const DEFAULT_SCOPE: &str = "snsapi_login";

/// UI language for the WeChat login page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WeChatLang {
    #[default]
    Cn,
    En,
}

impl WeChatLang {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::En => "en",
        }
    }
}

/// WeChat provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WeChatProviderOptions {
    pub oauth: ProviderOptions,
    pub lang: Option<WeChatLang>,
}

/// Input used to create a WeChat authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WeChatAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// WeChat user profile returned by `/sns/userinfo`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WeChatProfile {
    #[serde(default)]
    pub openid: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub headimgurl: String,
    #[serde(default)]
    pub privilege: Vec<String>,
    pub unionid: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// WeChat token response payload.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WeChatTokenResponse {
    pub access_token: Option<String>,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub openid: Option<String>,
    pub scope: Option<String>,
    pub unionid: Option<String>,
    pub errcode: Option<i64>,
    pub errmsg: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct WeChatErrorPayload {
    pub errcode: Option<i64>,
    pub errmsg: Option<String>,
}

/// User info plus raw WeChat profile data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeChatUserInfo {
    pub user: OAuth2UserInfo,
    pub data: WeChatProfile,
}

/// WeChat OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeChatProvider {
    options: WeChatProviderOptions,
}

pub fn wechat(oauth: ProviderOptions) -> WeChatProvider {
    WeChatProvider::new(WeChatProviderOptions {
        oauth,
        ..WeChatProviderOptions::default()
    })
}

impl WeChatProvider {
    pub fn new(options: WeChatProviderOptions) -> Self {
        Self { options }
    }

    pub fn id(&self) -> &str {
        WECHAT_ID
    }

    pub fn name(&self) -> &str {
        WECHAT_NAME
    }

    pub fn options(&self) -> &WeChatProviderOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: WeChatAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = Url::parse(WECHAT_AUTHORIZATION_ENDPOINT)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("scope", &self.scopes(request.scopes).join(","));
            query.append_pair("response_type", "code");
            query.append_pair("appid", self.client_id()?);
            query.append_pair(
                "redirect_uri",
                self.options
                    .oauth
                    .redirect_uri
                    .as_deref()
                    .unwrap_or(&request.redirect_uri),
            );
            query.append_pair("state", &request.state);
            query.append_pair("lang", self.options.lang.unwrap_or_default().as_str());
        }
        url.set_fragment(Some("wechat_redirect"));
        Ok(url)
    }

    pub fn authorization_code_url(&self, code: impl AsRef<str>) -> Result<Url, OAuthError> {
        let mut url = Url::parse(WECHAT_TOKEN_ENDPOINT)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("appid", self.client_id()?);
            query.append_pair("secret", self.client_secret()?);
            query.append_pair("code", code.as_ref());
            query.append_pair("grant_type", "authorization_code");
        }
        Ok(url)
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl AsRef<str>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let url = self.authorization_code_url(code)?;
        let response = crate::http::shared_client()
            .get(url)
            .send()
            .await?
            .error_for_status()?;
        let token_response = response.json::<WeChatTokenResponse>().await?;
        Self::tokens_from_response(token_response, true)
    }

    pub fn refresh_access_token_url(
        &self,
        refresh_token: impl AsRef<str>,
    ) -> Result<Url, OAuthError> {
        let _ = self.client_secret()?;
        let mut url = Url::parse(WECHAT_REFRESH_TOKEN_ENDPOINT)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("appid", self.client_id()?);
            query.append_pair("grant_type", "refresh_token");
            query.append_pair("refresh_token", refresh_token.as_ref());
        }
        Ok(url)
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl AsRef<str>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let url = self.refresh_access_token_url(refresh_token)?;
        let response = crate::http::shared_client()
            .get(url)
            .send()
            .await?
            .error_for_status()?;
        let token_response = response.json::<WeChatTokenResponse>().await?;
        Self::tokens_from_response(token_response, false)
    }

    pub fn user_info_url(&self, tokens: &OAuth2Tokens) -> Result<Option<Url>, OAuthError> {
        let Some(openid) = tokens.raw.get("openid").and_then(Value::as_str) else {
            return Ok(None);
        };

        let mut url = Url::parse(WECHAT_USER_INFO_ENDPOINT)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", tokens.access_token.as_deref().unwrap_or(""));
            query.append_pair("openid", openid);
            query.append_pair("lang", "zh_CN");
        }
        Ok(Some(url))
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<WeChatUserInfo>, OAuthError> {
        let Some(url) = self.user_info_url(tokens)? else {
            return Ok(None);
        };
        let response = match crate::http::shared_client().get(url).send().await {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        let data = match response.json::<Value>().await {
            Ok(data) => data,
            Err(_) => return Ok(None),
        };
        if wechat_error_message(&data).is_some() {
            return Ok(None);
        }
        let profile = match serde_json::from_value::<WeChatProfile>(data) {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::map_profile(profile)))
    }

    pub fn map_profile(profile: WeChatProfile) -> WeChatUserInfo {
        let user = Self::map_profile_to_user_info(&profile);
        WeChatUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_profile_to_user_info(profile: &WeChatProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile
                .unionid
                .clone()
                .unwrap_or_else(|| profile.openid.clone()),
            name: Some(profile.nickname.clone()),
            email: None,
            image: Some(profile.headimgurl.clone()),
            email_verified: false,
        }
    }

    fn tokens_from_response(
        token_response: WeChatTokenResponse,
        include_openid: bool,
    ) -> Result<OAuth2Tokens, OAuthError> {
        if let Some(message) = token_response.error_message() {
            return Err(OAuthError::InvalidResponse(message));
        }

        let access_token = required_field(token_response.access_token.as_deref(), "access_token")?;
        let refresh_token =
            required_field(token_response.refresh_token.as_deref(), "refresh_token")?;
        let expires_in = token_response.expires_in.ok_or_else(|| {
            OAuthError::InvalidResponse("WeChat token response missing `expires_in`".to_owned())
        })?;
        let scope = token_response.scope.as_deref().unwrap_or_default();
        let raw = serde_json::to_value(&token_response)
            .map_err(|error| OAuthError::InvalidResponse(error.to_string()))?;

        let openid = if include_openid {
            Some(required_field(token_response.openid.as_deref(), "openid")?)
        } else {
            token_response.openid
        };

        let mut raw = raw;
        if let Some(raw_object) = raw.as_object_mut() {
            if let Some(openid) = openid {
                raw_object.insert("openid".to_owned(), Value::String(openid));
            }
            if let Some(unionid) = token_response.unionid {
                raw_object.insert("unionid".to_owned(), Value::String(unionid));
            }
        }

        Ok(OAuth2Tokens {
            token_type: Some("Bearer".to_owned()),
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            access_token_expires_at: Some(
                OffsetDateTime::now_utc() + Duration::seconds(expires_in),
            ),
            refresh_token_expires_at: None,
            scopes: split_wechat_scopes(scope),
            id_token: None,
            raw,
        })
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            vec![DEFAULT_SCOPE.to_owned()]
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn client_id(&self) -> Result<&str, OAuthError> {
        get_primary_client_id(&self.options.oauth.client_id)
            .ok_or(OAuthError::MissingOption("client_id"))
    }

    fn client_secret(&self) -> Result<&str, OAuthError> {
        self.options
            .oauth
            .client_secret
            .as_deref()
            .ok_or(OAuthError::MissingOption("client_secret"))
    }
}

impl WeChatTokenResponse {
    fn error_message(&self) -> Option<String> {
        self.errcode.map(|_| {
            format!(
                "WeChat OAuth error: {}",
                self.errmsg.as_deref().unwrap_or("Unknown error")
            )
        })
    }
}

impl Default for WeChatProvider {
    fn default() -> Self {
        Self::new(WeChatProviderOptions::default())
    }
}

impl OAuthProviderContract for WeChatProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

fn required_field(value: Option<&str>, field: &'static str) -> Result<String, OAuthError> {
    value
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            OAuthError::InvalidResponse(format!("WeChat token response missing `{field}`"))
        })
}

fn split_wechat_scopes(scope: &str) -> Vec<String> {
    scope
        .split(',')
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

fn wechat_error_message(value: &Value) -> Option<String> {
    let payload = serde_json::from_value::<WeChatErrorPayload>(value.clone()).ok()?;
    payload.errcode.map(|_| {
        format!(
            "WeChat OAuth error: {}",
            payload.errmsg.as_deref().unwrap_or("Unknown error")
        )
    })
}
