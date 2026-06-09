use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use openauth_core::db::{Session, User};
use openauth_core::error::OpenAuthError;
use openauth_core::options::RateLimitRule;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::models::SchemaClient;

type ClientReferenceFuture =
    Pin<Box<dyn Future<Output = Result<Option<String>, OpenAuthError>> + Send>>;
type ClientPrivilegesFuture = Pin<Box<dyn Future<Output = Result<bool, OpenAuthError>> + Send>>;
type JsonObjectFuture =
    Pin<Box<dyn Future<Output = Result<Map<String, Value>, OpenAuthError>> + Send>>;
type OptionalStringFuture =
    Pin<Box<dyn Future<Output = Result<Option<String>, OpenAuthError>> + Send>>;
type RequestUriFuture =
    Pin<Box<dyn Future<Output = Result<Option<Vec<(String, String)>>, OpenAuthError>> + Send>>;
type StringGeneratorFuture = Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send>>;
type BoolResolverFuture = Pin<Box<dyn Future<Output = Result<bool, OpenAuthError>> + Send>>;
type RefreshTokenEncodeFuture = Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send>>;
type RefreshTokenDecodeFuture =
    Pin<Box<dyn Future<Output = Result<RefreshTokenFormatDecodeOutput, OpenAuthError>> + Send>>;

/// Input passed to the OAuth client reference resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReferenceInput {
    pub user: Option<User>,
    pub session: Option<Session>,
}

/// Async callback that resolves the non-user owner of OAuth clients.
#[derive(Clone)]
pub struct ClientReferenceResolver {
    resolver: Arc<dyn Fn(ClientReferenceInput) -> ClientReferenceFuture + Send + Sync>,
}

impl ClientReferenceResolver {
    /// Create a resolver from an async function.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ClientReferenceInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<String>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: ClientReferenceInput,
    ) -> Result<Option<String>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for ClientReferenceResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientReferenceResolver(..)")
    }
}

impl PartialEq for ClientReferenceResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ClientReferenceResolver {}

#[derive(Clone, Default)]
pub struct TrustedClientCache {
    clients: Arc<RwLock<BTreeMap<String, SchemaClient>>>,
}

impl TrustedClientCache {
    pub fn get(&self, client_id: &str) -> Result<Option<SchemaClient>, OpenAuthError> {
        let clients = self
            .clients
            .read()
            .map_err(|_| OpenAuthError::Api("trusted client cache lock poisoned".to_owned()))?;
        Ok(clients.get(client_id).cloned())
    }

    pub fn insert(&self, client: SchemaClient) -> Result<(), OpenAuthError> {
        let mut clients = self
            .clients
            .write()
            .map_err(|_| OpenAuthError::Api("trusted client cache lock poisoned".to_owned()))?;
        clients.insert(client.client_id.clone(), client);
        Ok(())
    }
}

impl std::fmt::Debug for TrustedClientCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TrustedClientCache(..)")
    }
}

impl PartialEq for TrustedClientCache {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for TrustedClientCache {}

/// OAuth client-management action checked by [`ClientPrivilegesResolver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientPrivilegeAction {
    Create,
    Read,
    Update,
    Delete,
    List,
    Rotate,
}

/// Input passed to the OAuth client privileges resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPrivilegesInput {
    pub action: ClientPrivilegeAction,
    pub user: Option<User>,
    pub session: Option<Session>,
}

/// Async callback that authorizes OAuth client-management actions.
#[derive(Clone)]
pub struct ClientPrivilegesResolver {
    resolver: Arc<dyn Fn(ClientPrivilegesInput) -> ClientPrivilegesFuture + Send + Sync>,
}

impl ClientPrivilegesResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ClientPrivilegesInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: ClientPrivilegesInput) -> Result<bool, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for ClientPrivilegesResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientPrivilegesResolver(..)")
    }
}

impl PartialEq for ClientPrivilegesResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ClientPrivilegesResolver {}

/// Input passed to custom client secret hash callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecretHashInput {
    pub secret: String,
}

/// Async callback that hashes client secrets before persistence.
#[derive(Clone)]
pub struct ClientSecretHashResolver {
    resolver: Arc<dyn Fn(ClientSecretHashInput) -> StringGeneratorFuture + Send + Sync>,
}

impl ClientSecretHashResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ClientSecretHashInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: ClientSecretHashInput) -> Result<String, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for ClientSecretHashResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientSecretHashResolver(..)")
    }
}

impl PartialEq for ClientSecretHashResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ClientSecretHashResolver {}

/// Input passed to custom client secret verification callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecretVerifyInput {
    pub secret: String,
    pub stored_hash: String,
}

/// Async callback that verifies client secrets against stored values.
#[derive(Clone)]
pub struct ClientSecretVerifyResolver {
    resolver: Arc<dyn Fn(ClientSecretVerifyInput) -> BoolResolverFuture + Send + Sync>,
}

impl ClientSecretVerifyResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ClientSecretVerifyInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: ClientSecretVerifyInput) -> Result<bool, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for ClientSecretVerifyResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientSecretVerifyResolver(..)")
    }
}

impl PartialEq for ClientSecretVerifyResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ClientSecretVerifyResolver {}

/// Input passed to custom OAuth token hash callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHashInput {
    pub token: String,
    pub token_type: String,
}

/// Async callback that hashes OAuth tokens before lookup or persistence.
#[derive(Clone)]
pub struct TokenHashResolver {
    resolver: Arc<dyn Fn(TokenHashInput) -> StringGeneratorFuture + Send + Sync>,
}

impl TokenHashResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(TokenHashInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: TokenHashInput) -> Result<String, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for TokenHashResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenHashResolver(..)")
    }
}

impl PartialEq for TokenHashResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for TokenHashResolver {}

/// Input passed to advanced prompt redirect callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRedirectInput {
    pub user: User,
    pub session: Session,
    pub scopes: Vec<String>,
}

/// Async callback that may redirect an advanced prompt step to a page.
#[derive(Clone)]
pub struct PromptRedirectResolver {
    resolver: Arc<dyn Fn(PromptRedirectInput) -> OptionalStringFuture + Send + Sync>,
}

impl PromptRedirectResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(PromptRedirectInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<String>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: PromptRedirectInput,
    ) -> Result<Option<String>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for PromptRedirectResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PromptRedirectResolver(..)")
    }
}

impl PartialEq for PromptRedirectResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for PromptRedirectResolver {}

/// Async callback that decides whether an advanced prompt step should run.
#[derive(Clone)]
pub struct PromptShouldRedirectResolver {
    resolver: Arc<dyn Fn(PromptRedirectInput) -> BoolResolverFuture + Send + Sync>,
}

impl PromptShouldRedirectResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(PromptRedirectInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: PromptRedirectInput) -> Result<bool, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for PromptShouldRedirectResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PromptShouldRedirectResolver(..)")
    }
}

impl PartialEq for PromptShouldRedirectResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for PromptShouldRedirectResolver {}

/// Input passed to custom ID token claim callbacks.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomIdTokenClaimsInput {
    pub user: User,
    pub scopes: Vec<String>,
    pub metadata: Option<Value>,
}

/// Input passed to custom access token claim callbacks.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomAccessTokenClaimsInput {
    pub user: Option<User>,
    pub reference_id: Option<String>,
    pub scopes: Vec<String>,
    pub resource: Vec<String>,
    pub metadata: Option<Value>,
}

/// Async callback that provides additional access token or introspection claims.
#[derive(Clone)]
pub struct CustomAccessTokenClaimsResolver {
    resolver: Arc<dyn Fn(CustomAccessTokenClaimsInput) -> JsonObjectFuture + Send + Sync>,
}

impl CustomAccessTokenClaimsResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(CustomAccessTokenClaimsInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Map<String, Value>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: CustomAccessTokenClaimsInput,
    ) -> Result<Map<String, Value>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for CustomAccessTokenClaimsResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CustomAccessTokenClaimsResolver(..)")
    }
}

impl PartialEq for CustomAccessTokenClaimsResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CustomAccessTokenClaimsResolver {}

/// Async callback that provides additional ID token claims.
#[derive(Clone)]
pub struct CustomIdTokenClaimsResolver {
    resolver: Arc<dyn Fn(CustomIdTokenClaimsInput) -> JsonObjectFuture + Send + Sync>,
}

impl CustomIdTokenClaimsResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(CustomIdTokenClaimsInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Map<String, Value>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: CustomIdTokenClaimsInput,
    ) -> Result<Map<String, Value>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for CustomIdTokenClaimsResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CustomIdTokenClaimsResolver(..)")
    }
}

impl PartialEq for CustomIdTokenClaimsResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CustomIdTokenClaimsResolver {}

/// Input passed to custom token response field callbacks.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomTokenResponseFieldsInput {
    pub grant_type: GrantType,
    pub user: Option<User>,
    pub scopes: Vec<String>,
    pub metadata: Option<Value>,
}

/// Async callback that provides extra token response fields.
#[derive(Clone)]
pub struct CustomTokenResponseFieldsResolver {
    resolver: Arc<dyn Fn(CustomTokenResponseFieldsInput) -> JsonObjectFuture + Send + Sync>,
}

impl CustomTokenResponseFieldsResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(CustomTokenResponseFieldsInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Map<String, Value>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: CustomTokenResponseFieldsInput,
    ) -> Result<Map<String, Value>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for CustomTokenResponseFieldsResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CustomTokenResponseFieldsResolver(..)")
    }
}

impl PartialEq for CustomTokenResponseFieldsResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CustomTokenResponseFieldsResolver {}

/// Input passed to custom userinfo claim callbacks.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomUserInfoClaimsInput {
    pub user: User,
    pub scopes: Vec<String>,
    pub jwt: Value,
}

/// Async callback that provides additional userinfo claims.
#[derive(Clone)]
pub struct CustomUserInfoClaimsResolver {
    resolver: Arc<dyn Fn(CustomUserInfoClaimsInput) -> JsonObjectFuture + Send + Sync>,
}

impl CustomUserInfoClaimsResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(CustomUserInfoClaimsInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Map<String, Value>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: CustomUserInfoClaimsInput,
    ) -> Result<Map<String, Value>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for CustomUserInfoClaimsResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CustomUserInfoClaimsResolver(..)")
    }
}

impl PartialEq for CustomUserInfoClaimsResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CustomUserInfoClaimsResolver {}

/// Input passed to request URI resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUriResolverInput {
    pub request_uri: String,
    pub client_id: Option<String>,
}

/// Async callback that resolves pushed authorization request parameters.
#[derive(Clone)]
pub struct RequestUriResolver {
    resolver: Arc<dyn Fn(RequestUriResolverInput) -> RequestUriFuture + Send + Sync>,
}

impl RequestUriResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(RequestUriResolverInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<Vec<(String, String)>>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(
        &self,
        input: RequestUriResolverInput,
    ) -> Result<Option<Vec<(String, String)>>, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for RequestUriResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequestUriResolver(..)")
    }
}

impl PartialEq for RequestUriResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for RequestUriResolver {}

/// Async callback used to generate OAuth identifiers and token secrets.
#[derive(Clone)]
pub struct StringGeneratorResolver {
    resolver: Arc<dyn Fn() -> StringGeneratorFuture + Send + Sync>,
}

impl StringGeneratorResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move || Box::pin(resolver())),
        }
    }

    pub async fn generate(&self) -> Result<String, OpenAuthError> {
        (self.resolver)().await
    }
}

impl std::fmt::Debug for StringGeneratorResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StringGeneratorResolver(..)")
    }
}

impl PartialEq for StringGeneratorResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for StringGeneratorResolver {}

/// Input passed to custom refresh token formatters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenFormatEncodeInput {
    pub token: String,
    pub session_id: Option<String>,
}

/// Output returned from custom refresh token decoders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenFormatDecodeOutput {
    pub session_id: Option<String>,
    pub token: String,
}

/// Async callbacks that encode and decode refresh tokens returned to OAuth clients.
#[derive(Clone)]
pub struct RefreshTokenFormatter {
    encoder: Arc<dyn Fn(RefreshTokenFormatEncodeInput) -> RefreshTokenEncodeFuture + Send + Sync>,
    decoder: Arc<dyn Fn(String) -> RefreshTokenDecodeFuture + Send + Sync>,
}

impl RefreshTokenFormatter {
    pub fn new<Encode, EncodeFuture, Decode, DecodeFuture>(encoder: Encode, decoder: Decode) -> Self
    where
        Encode: Fn(RefreshTokenFormatEncodeInput) -> EncodeFuture + Send + Sync + 'static,
        EncodeFuture: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
        Decode: Fn(String) -> DecodeFuture + Send + Sync + 'static,
        DecodeFuture:
            Future<Output = Result<RefreshTokenFormatDecodeOutput, OpenAuthError>> + Send + 'static,
    {
        Self {
            encoder: Arc::new(move |input| Box::pin(encoder(input))),
            decoder: Arc::new(move |token| Box::pin(decoder(token))),
        }
    }

    pub async fn encode(
        &self,
        input: RefreshTokenFormatEncodeInput,
    ) -> Result<String, OpenAuthError> {
        (self.encoder)(input).await
    }

    pub async fn decode(
        &self,
        token: String,
    ) -> Result<RefreshTokenFormatDecodeOutput, OpenAuthError> {
        (self.decoder)(token).await
    }
}

impl std::fmt::Debug for RefreshTokenFormatter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RefreshTokenFormatter(..)")
    }
}

impl PartialEq for RefreshTokenFormatter {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for RefreshTokenFormatter {}

/// Optional public prefixes applied to generated OAuth secrets before returning them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthTokenPrefixes {
    pub opaque_access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub client_secret: Option<String>,
}

/// Supported token endpoint grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

impl GrantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// OAuth token endpoint client authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
}

/// Storage strategy for OAuth provider secrets and tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStorage {
    /// Choose the upstream default from the JWT plugin setting.
    Auto,
    /// Store only a hash of the value.
    Hashed,
    /// Store an encrypted value.
    Encrypted,
}

/// Per-endpoint OAuth provider rate-limit behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthProviderRateLimit {
    /// Use the provider's built-in default for this endpoint.
    Default,
    /// Do not contribute a plugin rate-limit rule for this endpoint.
    Disabled,
    /// Override the built-in default with a custom rule.
    Custom(RateLimitRule),
}

/// Rate-limit settings for OAuth provider endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderRateLimits {
    pub token: OAuthProviderRateLimit,
    pub authorize: OAuthProviderRateLimit,
    pub introspect: OAuthProviderRateLimit,
    pub revoke: OAuthProviderRateLimit,
    pub register: OAuthProviderRateLimit,
    pub userinfo: OAuthProviderRateLimit,
}

impl Default for OAuthProviderRateLimits {
    fn default() -> Self {
        Self {
            token: OAuthProviderRateLimit::Default,
            authorize: OAuthProviderRateLimit::Default,
            introspect: OAuthProviderRateLimit::Default,
            revoke: OAuthProviderRateLimit::Default,
            register: OAuthProviderRateLimit::Default,
            userinfo: OAuthProviderRateLimit::Default,
        }
    }
}

/// Metadata extension points for MCP discovery responses.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct McpMetadataOverrides {
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub authorization_server: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub protected_resource: Map<String, Value>,
}

/// MCP profile options. When enabled, the provider exposes MCP resource metadata.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpOptions {
    /// Protected resource identifier (RFC 9728). Defaults to the origin of `base_url`.
    pub resource: Option<String>,
    pub metadata: McpMetadataOverrides,
}

/// Resolved MCP options stored on the plugin after validation.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResolvedMcpOptions {
    pub resource: Option<String>,
    pub metadata: McpMetadataOverrides,
}

/// User-facing OAuth provider plugin options.
#[derive(Debug, Clone, PartialEq)]
pub struct OAuthProviderOptions {
    pub scopes: Vec<String>,
    pub client_registration_default_scopes: Vec<String>,
    pub client_registration_allowed_scopes: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub login_page: String,
    pub consent_page: String,
    pub signup_page: Option<String>,
    pub select_account_page: Option<String>,
    pub post_login_page: Option<String>,
    pub signup_redirect: Option<PromptRedirectResolver>,
    pub select_account_redirect: Option<PromptRedirectResolver>,
    pub post_login_redirect: Option<PromptRedirectResolver>,
    pub signup_should_redirect: Option<PromptShouldRedirectResolver>,
    pub select_account_should_redirect: Option<PromptShouldRedirectResolver>,
    pub post_login_should_redirect: Option<PromptShouldRedirectResolver>,
    pub consent_reference_id: Option<ClientReferenceResolver>,
    pub code_expires_in: u64,
    pub access_token_expires_in: u64,
    pub m2m_access_token_expires_in: u64,
    pub id_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub client_credential_grant_default_scopes: Vec<String>,
    pub scope_expirations: BTreeMap<String, u64>,
    pub client_registration_client_secret_expiration: Option<u64>,
    pub allow_unauthenticated_client_registration: bool,
    pub allow_dynamic_client_registration: bool,
    pub allow_public_client_prelogin: bool,
    pub cached_trusted_clients: BTreeSet<String>,
    pub client_reference: Option<ClientReferenceResolver>,
    pub client_privileges: Option<ClientPrivilegesResolver>,
    pub custom_access_token_claims: Option<CustomAccessTokenClaimsResolver>,
    pub custom_id_token_claims: Option<CustomIdTokenClaimsResolver>,
    pub custom_token_response_fields: Option<CustomTokenResponseFieldsResolver>,
    pub custom_userinfo_claims: Option<CustomUserInfoClaimsResolver>,
    pub request_uri_resolver: Option<RequestUriResolver>,
    pub prefixes: OAuthTokenPrefixes,
    pub generate_client_id: Option<StringGeneratorResolver>,
    pub generate_client_secret: Option<StringGeneratorResolver>,
    pub generate_opaque_access_token: Option<StringGeneratorResolver>,
    pub generate_refresh_token: Option<StringGeneratorResolver>,
    pub format_refresh_token: Option<RefreshTokenFormatter>,
    pub disable_jwt_plugin: bool,
    pub store_client_secret: SecretStorage,
    pub store_tokens: SecretStorage,
    pub hash_client_secret: Option<ClientSecretHashResolver>,
    pub verify_client_secret_hash: Option<ClientSecretVerifyResolver>,
    pub hash_token: Option<TokenHashResolver>,
    pub pairwise_secret: Option<String>,
    pub advertised_scopes_supported: Vec<String>,
    pub advertised_claims_supported: Vec<String>,
    pub advertised_jwks_uri: Option<String>,
    pub advertised_id_token_signing_algorithms: Vec<String>,
    pub jwks_path: String,
    pub valid_audiences: Vec<String>,
    pub rate_limits: OAuthProviderRateLimits,
    /// Enable MCP protected-resource metadata.
    pub mcp: Option<McpOptions>,
}

impl Default for OAuthProviderOptions {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            client_registration_default_scopes: Vec::new(),
            client_registration_allowed_scopes: Vec::new(),
            grant_types: Vec::new(),
            login_page: String::new(),
            consent_page: String::new(),
            signup_page: None,
            select_account_page: None,
            post_login_page: None,
            signup_redirect: None,
            select_account_redirect: None,
            post_login_redirect: None,
            signup_should_redirect: None,
            select_account_should_redirect: None,
            post_login_should_redirect: None,
            consent_reference_id: None,
            code_expires_in: 600,
            access_token_expires_in: 3600,
            m2m_access_token_expires_in: 3600,
            id_token_expires_in: 36000,
            refresh_token_expires_in: 2_592_000,
            client_credential_grant_default_scopes: Vec::new(),
            scope_expirations: BTreeMap::new(),
            client_registration_client_secret_expiration: None,
            allow_unauthenticated_client_registration: false,
            allow_dynamic_client_registration: false,
            allow_public_client_prelogin: false,
            cached_trusted_clients: BTreeSet::new(),
            client_reference: None,
            client_privileges: None,
            custom_access_token_claims: None,
            custom_id_token_claims: None,
            custom_token_response_fields: None,
            custom_userinfo_claims: None,
            request_uri_resolver: None,
            prefixes: OAuthTokenPrefixes::default(),
            generate_client_id: None,
            generate_client_secret: None,
            generate_opaque_access_token: None,
            generate_refresh_token: None,
            format_refresh_token: None,
            disable_jwt_plugin: false,
            store_client_secret: SecretStorage::Auto,
            store_tokens: SecretStorage::Hashed,
            hash_client_secret: None,
            verify_client_secret_hash: None,
            hash_token: None,
            pairwise_secret: None,
            advertised_scopes_supported: Vec::new(),
            advertised_claims_supported: Vec::new(),
            advertised_jwks_uri: None,
            advertised_id_token_signing_algorithms: Vec::new(),
            jwks_path: "/jwks".to_owned(),
            valid_audiences: Vec::new(),
            rate_limits: OAuthProviderRateLimits::default(),
            mcp: None,
        }
    }
}

/// Fully resolved OAuth provider options after upstream-compatible defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedOAuthProviderOptions {
    pub scopes: Vec<String>,
    pub claims: Vec<String>,
    pub client_registration_allowed_scopes: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub login_page: String,
    pub consent_page: String,
    pub signup_page: Option<String>,
    pub select_account_page: Option<String>,
    pub post_login_page: Option<String>,
    pub signup_redirect: Option<PromptRedirectResolver>,
    pub select_account_redirect: Option<PromptRedirectResolver>,
    pub post_login_redirect: Option<PromptRedirectResolver>,
    pub signup_should_redirect: Option<PromptShouldRedirectResolver>,
    pub select_account_should_redirect: Option<PromptShouldRedirectResolver>,
    pub post_login_should_redirect: Option<PromptShouldRedirectResolver>,
    pub consent_reference_id: Option<ClientReferenceResolver>,
    pub code_expires_in: u64,
    pub access_token_expires_in: u64,
    pub m2m_access_token_expires_in: u64,
    pub id_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub client_credential_grant_default_scopes: Vec<String>,
    pub scope_expirations: BTreeMap<String, u64>,
    pub client_registration_default_scopes: Vec<String>,
    pub client_registration_client_secret_expiration: Option<u64>,
    pub allow_unauthenticated_client_registration: bool,
    pub allow_dynamic_client_registration: bool,
    pub allow_public_client_prelogin: bool,
    pub cached_trusted_clients: BTreeSet<String>,
    pub trusted_client_cache: TrustedClientCache,
    pub client_reference: Option<ClientReferenceResolver>,
    pub client_privileges: Option<ClientPrivilegesResolver>,
    pub custom_access_token_claims: Option<CustomAccessTokenClaimsResolver>,
    pub custom_id_token_claims: Option<CustomIdTokenClaimsResolver>,
    pub custom_token_response_fields: Option<CustomTokenResponseFieldsResolver>,
    pub custom_userinfo_claims: Option<CustomUserInfoClaimsResolver>,
    pub request_uri_resolver: Option<RequestUriResolver>,
    pub prefixes: OAuthTokenPrefixes,
    pub generate_client_id: Option<StringGeneratorResolver>,
    pub generate_client_secret: Option<StringGeneratorResolver>,
    pub generate_opaque_access_token: Option<StringGeneratorResolver>,
    pub generate_refresh_token: Option<StringGeneratorResolver>,
    pub format_refresh_token: Option<RefreshTokenFormatter>,
    pub disable_jwt_plugin: bool,
    pub store_client_secret: SecretStorage,
    pub store_tokens: SecretStorage,
    pub hash_client_secret: Option<ClientSecretHashResolver>,
    pub verify_client_secret_hash: Option<ClientSecretVerifyResolver>,
    pub hash_token: Option<TokenHashResolver>,
    pub pairwise_secret: Option<String>,
    pub advertised_scopes_supported: Vec<String>,
    pub advertised_claims_supported: Vec<String>,
    pub advertised_jwks_uri: Option<String>,
    pub advertised_id_token_signing_algorithms: Vec<String>,
    pub jwks_path: String,
    pub valid_audiences: Vec<String>,
    pub rate_limits: OAuthProviderRateLimits,
    pub mcp: Option<ResolvedMcpOptions>,
}

/// OAuth provider configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OAuthProviderConfigError {
    #[error("login_page is required")]
    MissingLoginPage,
    #[error("consent_page is required")]
    MissingConsentPage,
    #[error("clientRegistrationAllowedScope {0} not found in scopes")]
    UnknownClientRegistrationScope(String),
    #[error("clientCredentialGrantDefaultScopes {0} not found in scopes")]
    UnknownClientCredentialGrantScope(String),
    #[error("advertisedMetadata.scopes_supported {0} not found in scopes")]
    UnknownAdvertisedScope(String),
    #[error(
        "pairwiseSecret must be at least 32 characters long for adequate HMAC-SHA256 security"
    )]
    PairwiseSecretTooShort,
    #[error("refresh_token grant requires authorization_code grant")]
    RefreshTokenRequiresAuthorizationCode,
    #[error("unable to store hashed secrets because id tokens will be signed with secret")]
    HashedClientSecretsRequireJwtPlugin,
    #[error("encryption method not recommended, please use 'hashed' or the 'hash' function")]
    EncryptedClientSecretsWithJwtPlugin,
    #[error("mcp.resource must be a valid absolute URL when set")]
    InvalidMcpResource,
    #[error("unable to initialize jwt plugin: {0}")]
    JwtPlugin(String),
}
