//! Microsoft Entra ID social OAuth provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, get_primary_client_id,
    refresh_access_token, refresh_access_token_request, validate_authorization_code,
    validate_token_with_client, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientAuthentication, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthFormRequest, OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest,
    TokenValidationOptions,
};

use crate::http::ValidationHttpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const MICROSOFT_ENTRA_ID_ID: &str = "microsoft";
pub const MICROSOFT_ENTRA_ID_NAME: &str = "Microsoft EntraID";
pub const MICROSOFT_ENTRA_ID_DEFAULT_TENANT: &str = "common";
pub const MICROSOFT_ENTRA_ID_DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com";
pub const MICROSOFT_ENTRA_ID_GRAPH_PHOTO_BASE_URL: &str =
    "https://graph.microsoft.com/v1.0/me/photos";
/// Microsoft consumer (MSA) tenant used by personal Microsoft accounts.
const MICROSOFT_CONSUMER_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MicrosoftEntraIdPhotoSize {
    #[default]
    Size48,
    Size64,
    Size96,
    Size120,
    Size240,
    Size360,
    Size432,
    Size504,
    Size648,
}

impl MicrosoftEntraIdPhotoSize {
    fn as_u16(self) -> u16 {
        match self {
            Self::Size48 => 48,
            Self::Size64 => 64,
            Self::Size96 => 96,
            Self::Size120 => 120,
            Self::Size240 => 240,
            Self::Size360 => 360,
            Self::Size432 => 432,
            Self::Size504 => 504,
            Self::Size648 => 648,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrosoftEntraIdOptions {
    pub oauth: ProviderOptions,
    pub tenant_id: Option<String>,
    pub authority: Option<String>,
    pub profile_photo_size: MicrosoftEntraIdPhotoSize,
    pub disable_profile_photo: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrosoftEntraIdAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrosoftEntraIdAuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MicrosoftEntraIdProfile {
    pub aud: Option<Value>,
    pub iss: Option<String>,
    pub iat: Option<i64>,
    pub idp: Option<String>,
    pub nbf: Option<i64>,
    pub exp: Option<i64>,
    pub c_hash: Option<String>,
    pub at_hash: Option<String>,
    pub aio: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub picture: Option<String>,
    pub oid: Option<String>,
    pub roles: Vec<String>,
    pub rh: Option<String>,
    pub sub: String,
    pub tid: Option<String>,
    pub sid: Option<String>,
    pub uti: Option<String>,
    pub hasgroups: Option<bool>,
    pub acct: Option<u8>,
    pub acrs: Option<String>,
    pub auth_time: Option<i64>,
    pub ctry: Option<String>,
    pub fwd: Option<String>,
    pub groups: Option<Value>,
    pub login_hint: Option<String>,
    pub tenant_ctry: Option<String>,
    pub tenant_region_scope: Option<String>,
    pub upn: Option<String>,
    pub verified_primary_email: Vec<String>,
    pub verified_secondary_email: Vec<String>,
    pub email_verified: Option<bool>,
    pub vnet: Option<String>,
    pub xms_cc: Option<Value>,
    pub xms_edov: Option<bool>,
    pub xms_pdl: Option<String>,
    pub xms_pl: Option<String>,
    pub xms_tpl: Option<String>,
    pub ztdid: Option<String>,
    pub ipaddr: Option<String>,
    pub onprem_sid: Option<String>,
    pub pwd_exp: Option<i64>,
    pub pwd_url: Option<String>,
    pub in_corp: Option<String>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MicrosoftEntraIdUserInfo {
    pub user: OAuth2UserInfo,
    pub data: MicrosoftEntraIdProfile,
}

#[derive(Debug, Clone)]
pub struct MicrosoftEntraIdProvider {
    options: MicrosoftEntraIdOptions,
    tenant: String,
    authority: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_endpoint: String,
    validation_http_client: ValidationHttpClient,
}

pub fn microsoft_entra_id(options: MicrosoftEntraIdOptions) -> MicrosoftEntraIdProvider {
    MicrosoftEntraIdProvider::new(options)
}

impl MicrosoftEntraIdProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.sub.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            image: self.picture.clone(),
            email_verified: self.email_verified.unwrap_or_else(|| {
                self.email.as_ref().is_some_and(|email| {
                    self.verified_primary_email
                        .iter()
                        .any(|candidate| candidate == email)
                        || self
                            .verified_secondary_email
                            .iter()
                            .any(|candidate| candidate == email)
                })
            }),
        }
    }
}

impl MicrosoftEntraIdProvider {
    pub fn new(options: MicrosoftEntraIdOptions) -> Self {
        let tenant = normalize_tenant(options.tenant_id.as_deref());
        let authority = normalize_authority(options.authority.as_deref());
        let authorization_endpoint = format!("{authority}/{tenant}/oauth2/v2.0/authorize");
        let token_endpoint = format!("{authority}/{tenant}/oauth2/v2.0/token");
        let jwks_endpoint = format!("{authority}/{tenant}/discovery/v2.0/keys");

        Self {
            options,
            tenant,
            authority,
            authorization_endpoint,
            token_endpoint,
            jwks_endpoint,
            validation_http_client: ValidationHttpClient::shared(),
        }
    }

    pub fn options(&self) -> &MicrosoftEntraIdOptions {
        &self.options
    }

    /// Overrides the HTTP client used for JWKS and ID-token validation.
    pub fn with_validation_http_client(mut self, client: ValidationHttpClient) -> Self {
        self.validation_http_client = client;
        self
    }

    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub fn jwks_endpoint(&self) -> &str {
        &self.jwks_endpoint
    }

    pub fn create_authorization_url(
        &self,
        input: MicrosoftEntraIdAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        if get_primary_client_id(&self.options.oauth.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }

        let mut scopes = self.scopes();
        scopes.extend(input.scopes);

        create_authorization_url(AuthorizationUrlRequest {
            id: MICROSOFT_ENTRA_ID_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            redirect_uri: input.redirect_uri,
            state: input.state,
            code_verifier: input.code_verifier,
            scopes,
            prompt: self.options.oauth.prompt.clone(),
            login_hint: input.login_hint,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        input: MicrosoftEntraIdAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: input.code,
            redirect_uri: input.redirect_uri,
            options: self.options.oauth.clone(),
            code_verifier: input.code_verifier,
            device_id: input.device_id,
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        input: MicrosoftEntraIdAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: AuthorizationCodeRequest {
                code: input.code,
                redirect_uri: input.redirect_uri,
                options: self.options.oauth.clone(),
                code_verifier: input.code_verifier,
                device_id: input.device_id,
                authentication: ClientAuthentication::Post,
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token.into(),
            options: ProviderOptions {
                client_id: self.options.oauth.client_id.clone(),
                client_secret: self.options.oauth.client_secret.clone(),
                ..ProviderOptions::default()
            },
            authentication: ClientAuthentication::Post,
            extra_params: BTreeMap::from([("scope".to_owned(), self.scopes().join(" "))]),
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: ProviderOptions {
                    client_id: self.options.oauth.client_id.clone(),
                    client_secret: self.options.oauth.client_secret.clone(),
                    ..ProviderOptions::default()
                },
                authentication: ClientAuthentication::Post,
                extra_params: BTreeMap::from([("scope".to_owned(), self.scopes().join(" "))]),
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        self.verify_id_token_with_jwks_url(token, nonce, &self.jwks_endpoint)
            .await
    }

    pub async fn verify_id_token_with_jwks_url(
        &self,
        token: &str,
        nonce: Option<&str>,
        jwks_url: &str,
    ) -> Result<bool, OAuthError> {
        if self.options.oauth.disable_id_token_sign_in {
            return Ok(false);
        }

        let audiences = self.client_id_audiences();
        if audiences.is_empty() {
            return Ok(false);
        }

        let expected_issuers = self.expected_issuers();
        let validate_multitenant_issuer = expected_issuers.is_empty();

        let result = match validate_token_with_client(
            token,
            jwks_url,
            TokenValidationOptions {
                audience: audiences,
                issuer: expected_issuers,
                ..TokenValidationOptions::default().require_standard_claims()
            },
            self.validation_http_client.inner(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => return Ok(false),
        };

        if validate_multitenant_issuer {
            let issuer = result.payload.get("iss").and_then(Value::as_str);
            if !issuer.is_some_and(|issuer| self.accepts_multitenant_issuer(issuer)) {
                return Ok(false);
            }
        }

        if let Some(expected_nonce) = nonce {
            let actual_nonce = result.payload.get("nonce").and_then(Value::as_str);
            if actual_nonce != Some(expected_nonce) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn get_user_info_from_tokens(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<MicrosoftEntraIdUserInfo>, OAuthError> {
        let Some(id_token) = token.id_token.as_deref() else {
            return Ok(None);
        };
        let profile = decode_jwt_payload::<MicrosoftEntraIdProfile>(id_token)?;
        Ok(Some(MicrosoftEntraIdUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<MicrosoftEntraIdUserInfo>, OAuthError> {
        let Some(mut info) = self.get_user_info_from_tokens(token)? else {
            return Ok(None);
        };

        if !self.options.disable_profile_photo {
            if let Some(access_token) = token.access_token.as_deref() {
                if let Some(picture) = self
                    .fetch_profile_photo(access_token, MICROSOFT_ENTRA_ID_GRAPH_PHOTO_BASE_URL)
                    .await
                {
                    info.data.picture = Some(picture.clone());
                    info.user.image = Some(picture);
                }
            }
        }

        Ok(Some(info))
    }

    fn scopes(&self) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            ["openid", "profile", "email", "User.Read", "offline_access"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes
    }

    fn client_id_audiences(&self) -> Vec<String> {
        match &self.options.oauth.client_id {
            Some(openauth_oauth::oauth2::ClientId::Single(value)) if !value.is_empty() => {
                vec![value.clone()]
            }
            Some(openauth_oauth::oauth2::ClientId::Multiple(values)) => values
                .iter()
                .filter(|value| !value.is_empty())
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }

    fn expected_issuers(&self) -> Vec<String> {
        if matches!(
            self.tenant.as_str(),
            "common" | "organizations" | "consumers"
        ) {
            return Vec::new();
        }
        vec![format!("{}/{}/v2.0", self.authority, self.tenant)]
    }

    /// Binds a multi-tenant (`common`/`organizations`/`consumers`) issuer to the
    /// configured authority and tenant semantics, since these modes cannot be
    /// expressed as a static issuer list.
    fn accepts_multitenant_issuer(&self, issuer: &str) -> bool {
        let Some(tenant_id) = self.issuer_tenant_id(issuer) else {
            return false;
        };
        if !is_tenant_guid(tenant_id) {
            return false;
        }
        match self.tenant.as_str() {
            "consumers" => tenant_id.eq_ignore_ascii_case(MICROSOFT_CONSUMER_TENANT_ID),
            "organizations" => !tenant_id.eq_ignore_ascii_case(MICROSOFT_CONSUMER_TENANT_ID),
            _ => true,
        }
    }

    /// Extracts the tenant segment from an `{authority}/{tenant}/v2.0` issuer
    /// built from the configured authority.
    fn issuer_tenant_id<'a>(&self, issuer: &'a str) -> Option<&'a str> {
        let tenant = issuer
            .strip_prefix(&format!("{}/", self.authority))?
            .strip_suffix("/v2.0")?;
        (!tenant.is_empty() && !tenant.contains('/')).then_some(tenant)
    }

    async fn fetch_profile_photo(&self, access_token: &str, base_url: &str) -> Option<String> {
        let size = self.options.profile_photo_size.as_u16();
        let base_url = base_url.trim_end_matches('/');
        let url = format!("{base_url}/{size}x{size}/$value");
        let response = crate::http::shared_client()
            .get(url)
            .header("authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let bytes = response.bytes().await.ok()?;
        Some(format!(
            "data:image/jpeg;base64, {}",
            STANDARD.encode(bytes)
        ))
    }
}

impl OAuthProviderContract for MicrosoftEntraIdProvider {
    fn id(&self) -> &str {
        MICROSOFT_ENTRA_ID_ID
    }

    fn name(&self) -> &str {
        MICROSOFT_ENTRA_ID_NAME
    }
}

fn normalize_tenant(tenant: Option<&str>) -> String {
    let tenant = tenant.unwrap_or(MICROSOFT_ENTRA_ID_DEFAULT_TENANT).trim();
    let tenant = tenant.trim_matches('/');
    if tenant.is_empty() {
        MICROSOFT_ENTRA_ID_DEFAULT_TENANT.to_owned()
    } else {
        tenant.to_owned()
    }
}

fn normalize_authority(authority: Option<&str>) -> String {
    let authority = authority
        .unwrap_or(MICROSOFT_ENTRA_ID_DEFAULT_AUTHORITY)
        .trim();
    let authority = authority.trim_end_matches('/');
    if authority.is_empty() {
        MICROSOFT_ENTRA_ID_DEFAULT_AUTHORITY.to_owned()
    } else {
        authority.to_owned()
    }
}

/// Returns `true` when `value` is a canonical 8-4-4-4-12 GUID, the shape of a
/// Microsoft tenant identifier in a v2.0 issuer.
fn is_tenant_guid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, OAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt payload".to_owned()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| OAuthError::TokenVerification(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "Microsoft Entra ID provider tests intentionally fail fast with contextual setup errors"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_profile_photo_returns_data_url_when_graph_photo_is_available() {
        let server = BinaryServer::spawn(b"fake-jpeg".to_vec(), 200);
        let provider = MicrosoftEntraIdProvider::new(MicrosoftEntraIdOptions {
            profile_photo_size: MicrosoftEntraIdPhotoSize::Size64,
            ..MicrosoftEntraIdOptions::default()
        });

        let picture = provider
            .fetch_profile_photo("access-token", &server.url())
            .await
            .expect("photo should be returned");

        assert_eq!(picture, "data:image/jpeg;base64, ZmFrZS1qcGVn");
    }

    struct BinaryServer {
        url: String,
    }

    impl BinaryServer {
        fn spawn(body: Vec<u8>, status: u16) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("server should bind");
            let addr = listener.local_addr().expect("server address");
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buffer);
                let response_head = format!(
                    "HTTP/1.1 {status} OK\r\ncontent-type: image/jpeg\r\ncontent-length: {}\r\n\r\n",
                    body.len()
                );
                std::io::Write::write_all(&mut stream, response_head.as_bytes())
                    .expect("response head should write");
                std::io::Write::write_all(&mut stream, &body).expect("response body should write");
            });
            Self {
                url: format!("http://{addr}"),
            }
        }

        fn url(&self) -> String {
            self.url.clone()
        }
    }
}
