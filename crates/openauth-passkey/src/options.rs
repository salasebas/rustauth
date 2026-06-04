use std::future::{ready, Future};
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::options::RateLimitRule;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::webauthn::{PasskeyWebAuthnBackend, RealPasskeyWebAuthnBackend};

/// Rate limit settings for passkey ceremony endpoints (challenge generation and verification).
///
/// Defaults match OpenAuth core's strict sign-in policy (`3` requests per `10` seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyRateLimit {
    pub window: u64,
    pub max: u64,
}

impl Default for PasskeyRateLimit {
    fn default() -> Self {
        Self { window: 10, max: 3 }
    }
}

impl PasskeyRateLimit {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn window(mut self, window: u64) -> Self {
        self.window = window;
        self
    }

    #[must_use]
    pub fn max(mut self, max: u64) -> Self {
        self.max = max;
        self
    }
}

/// Per signed challenge cookie rate limits for passkey verify endpoints.
///
/// Limits verification attempts per challenge independently of the ceremony
/// IP+path bucket. Storage keys use `HMAC-SHA256(secret, challenge_token)` via
/// OpenAuth core; raw tokens are never persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyChallengeRateLimit {
    pub window: u64,
    pub max: u64,
}

impl Default for PasskeyChallengeRateLimit {
    fn default() -> Self {
        Self {
            window: 60 * 5,
            max: 5,
        }
    }
}

impl PasskeyChallengeRateLimit {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn window(mut self, window: u64) -> Self {
        self.window = window;
        self
    }

    #[must_use]
    pub fn max(mut self, max: u64) -> Self {
        self.max = max;
        self
    }

    /// Disable per-challenge verification rate limiting.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.max = 0;
        self
    }

    pub(crate) fn rule(&self) -> Option<RateLimitRule> {
        if self.max == 0 || self.window == 0 {
            return None;
        }
        Some(RateLimitRule {
            window: self.window,
            max: self.max,
        })
    }
}

/// Advanced passkey plugin settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAdvancedOptions {
    pub webauthn_challenge_cookie: String,
}

impl Default for PasskeyAdvancedOptions {
    fn default() -> Self {
        Self {
            webauthn_challenge_cookie: "better-auth-passkey".to_owned(),
        }
    }
}

/// Passkey plugin settings.
#[derive(Clone)]
pub struct PasskeyOptions {
    pub rp_id: Option<String>,
    pub rp_name: Option<String>,
    pub origin: Vec<String>,
    pub passkey_table: String,
    pub authenticator_selection: AuthenticatorSelection,
    pub registration: PasskeyRegistrationOptions,
    pub authentication: PasskeyAuthenticationOptions,
    pub advanced: PasskeyAdvancedOptions,
    pub rate_limit: PasskeyRateLimit,
    pub challenge_rate_limit: PasskeyChallengeRateLimit,
    pub backend: Arc<dyn PasskeyWebAuthnBackend>,
}

impl Default for PasskeyOptions {
    fn default() -> Self {
        Self {
            rp_id: None,
            rp_name: None,
            origin: Vec::new(),
            passkey_table: "passkeys".to_owned(),
            authenticator_selection: AuthenticatorSelection::default(),
            registration: PasskeyRegistrationOptions::default(),
            authentication: PasskeyAuthenticationOptions::default(),
            advanced: PasskeyAdvancedOptions::default(),
            rate_limit: PasskeyRateLimit::default(),
            challenge_rate_limit: PasskeyChallengeRateLimit::default(),
            backend: Arc::new(RealPasskeyWebAuthnBackend),
        }
    }
}

impl PasskeyOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn rp_id(mut self, rp_id: impl Into<String>) -> Self {
        self.rp_id = Some(rp_id.into());
        self
    }

    #[must_use]
    pub fn rp_name(mut self, rp_name: impl Into<String>) -> Self {
        self.rp_name = Some(rp_name.into());
        self
    }

    #[must_use]
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin.push(origin.into());
        self
    }

    #[must_use]
    pub fn passkey_table(mut self, table: impl Into<String>) -> Self {
        self.passkey_table = table.into();
        self
    }

    #[must_use]
    pub fn authenticator_selection(mut self, selection: AuthenticatorSelection) -> Self {
        self.authenticator_selection = selection;
        self
    }

    #[must_use]
    pub fn registration(mut self, registration: PasskeyRegistrationOptions) -> Self {
        self.registration = registration;
        self
    }

    #[must_use]
    pub fn authentication(mut self, authentication: PasskeyAuthenticationOptions) -> Self {
        self.authentication = authentication;
        self
    }

    #[must_use]
    pub fn advanced(mut self, advanced: PasskeyAdvancedOptions) -> Self {
        self.advanced = advanced;
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, rate_limit: PasskeyRateLimit) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    pub fn challenge_rate_limit(mut self, challenge_rate_limit: PasskeyChallengeRateLimit) -> Self {
        self.challenge_rate_limit = challenge_rate_limit;
        self
    }

    #[must_use]
    pub fn backend(mut self, backend: Arc<dyn PasskeyWebAuthnBackend>) -> Self {
        self.backend = backend;
        self
    }

    pub(crate) fn rate_limit_rule(&self) -> RateLimitRule {
        RateLimitRule {
            window: self.rate_limit.window,
            max: self.rate_limit.max,
        }
    }
}

/// Browser authenticator attachment hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

impl AuthenticatorAttachment {
    pub(crate) fn from_query(value: &str) -> Option<Self> {
        match value {
            "platform" => Some(Self::Platform),
            "cross-platform" => Some(Self::CrossPlatform),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::CrossPlatform => "cross-platform",
        }
    }
}

/// Resident key preference used in registration options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

impl ResidentKeyRequirement {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Discouraged => "discouraged",
            Self::Preferred => "preferred",
            Self::Required => "required",
        }
    }
}

/// User verification preference used in WebAuthn options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserVerificationRequirement {
    Discouraged,
    Preferred,
    Required,
}

impl UserVerificationRequirement {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Discouraged => "discouraged",
            Self::Preferred => "preferred",
            Self::Required => "required",
        }
    }
}

/// Authenticator selection hints for generated registration options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub resident_key: ResidentKeyRequirement,
    pub user_verification: UserVerificationRequirement,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

impl Default for AuthenticatorSelection {
    fn default() -> Self {
        Self {
            resident_key: ResidentKeyRequirement::Preferred,
            user_verification: UserVerificationRequirement::Preferred,
            authenticator_attachment: None,
        }
    }
}

impl AuthenticatorSelection {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn resident_key(mut self, resident_key: ResidentKeyRequirement) -> Self {
        self.resident_key = resident_key;
        self
    }

    #[must_use]
    pub fn user_verification(mut self, user_verification: UserVerificationRequirement) -> Self {
        self.user_verification = user_verification;
        self
    }

    #[must_use]
    pub fn authenticator_attachment(mut self, attachment: AuthenticatorAttachment) -> Self {
        self.authenticator_attachment = Some(attachment);
        self
    }

    pub(crate) fn with_attachment_override(
        &self,
        attachment: Option<AuthenticatorAttachment>,
    ) -> Self {
        let mut selection = self.clone();
        if attachment.is_some() {
            selection.authenticator_attachment = attachment;
        }
        selection
    }

    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "residentKey": self.resident_key.as_str(),
            "userVerification": self.user_verification.as_str(),
        });
        if let Some(attachment) = self.authenticator_attachment {
            value["authenticatorAttachment"] = json!(attachment.as_str());
        }
        value
    }
}

/// WebAuthn option customizations resolved for one registration request.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationWebAuthnOptions {
    pub authenticator_selection: AuthenticatorSelection,
    pub extensions: Option<Value>,
}

impl RegistrationWebAuthnOptions {
    pub(crate) fn new(
        authenticator_selection: AuthenticatorSelection,
        extensions: Option<Value>,
    ) -> Self {
        Self {
            authenticator_selection,
            extensions,
        }
    }
}

/// User identity used for passkey registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyRegistrationUser {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
}

impl PasskeyRegistrationUser {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            display_name: None,
        }
    }

    #[must_use]
    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

pub type PasskeyBoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub type ResolveRegistrationUser = Arc<
    dyn Fn(ResolveRegistrationUserInput) -> PasskeyBoxFuture<Option<PasskeyRegistrationUser>>
        + Send
        + Sync,
>;

pub type AfterRegistrationVerification = Arc<
    dyn Fn(AfterRegistrationVerificationInput) -> PasskeyBoxFuture<Option<String>> + Send + Sync,
>;

pub type AfterAuthenticationVerification =
    Arc<dyn Fn(AfterAuthenticationVerificationInput) -> PasskeyBoxFuture<()> + Send + Sync>;

pub type PasskeyExtensionsResolver =
    Arc<dyn Fn(PasskeyExtensionsInput) -> PasskeyBoxFuture<Option<Value>> + Send + Sync>;

#[derive(Clone)]
pub struct PasskeyRegistrationOptions {
    pub require_session: bool,
    pub resolve_user: Option<ResolveRegistrationUser>,
    pub after_verification: Option<AfterRegistrationVerification>,
    pub extensions: Option<PasskeyExtensionsResolver>,
}

impl Default for PasskeyRegistrationOptions {
    fn default() -> Self {
        Self {
            require_session: true,
            resolve_user: None,
            after_verification: None,
            extensions: None,
        }
    }
}

impl PasskeyRegistrationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn require_session(mut self, require_session: bool) -> Self {
        self.require_session = require_session;
        self
    }

    #[must_use]
    pub fn resolve_user<F>(mut self, resolver: F) -> Self
    where
        F: Fn(ResolveRegistrationUserInput) -> Option<PasskeyRegistrationUser>
            + Send
            + Sync
            + 'static,
    {
        self.resolve_user = Some(Arc::new(move |input| Box::pin(ready(resolver(input)))));
        self
    }

    #[must_use]
    pub fn resolve_user_async<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(ResolveRegistrationUserInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<PasskeyRegistrationUser>> + Send + 'static,
    {
        self.resolve_user = Some(Arc::new(move |input| Box::pin(resolver(input))));
        self
    }

    #[must_use]
    pub fn after_verification<F>(mut self, callback: F) -> Self
    where
        F: Fn(AfterRegistrationVerificationInput) -> Option<String> + Send + Sync + 'static,
    {
        self.after_verification = Some(Arc::new(move |input| Box::pin(ready(callback(input)))));
        self
    }

    #[must_use]
    pub fn after_verification_async<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(AfterRegistrationVerificationInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        self.after_verification = Some(Arc::new(move |input| Box::pin(callback(input))));
        self
    }

    #[must_use]
    pub fn extensions(mut self, extensions: Value) -> Self {
        self.extensions = Some(Arc::new(move |_| Box::pin(ready(Some(extensions.clone())))));
        self
    }

    #[must_use]
    pub fn extensions_resolver<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(PasskeyExtensionsInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Value>> + Send + 'static,
    {
        self.extensions = Some(Arc::new(move |input| Box::pin(resolver(input))));
        self
    }
}

#[derive(Clone, Default)]
pub struct PasskeyAuthenticationOptions {
    pub after_verification: Option<AfterAuthenticationVerification>,
    pub extensions: Option<PasskeyExtensionsResolver>,
}

impl PasskeyAuthenticationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn after_verification<F>(mut self, callback: F) -> Self
    where
        F: Fn(AfterAuthenticationVerificationInput) + Send + Sync + 'static,
    {
        self.after_verification = Some(Arc::new(move |input| {
            callback(input);
            Box::pin(ready(()))
        }));
        self
    }

    #[must_use]
    pub fn after_verification_async<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(AfterAuthenticationVerificationInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.after_verification = Some(Arc::new(move |input| Box::pin(callback(input))));
        self
    }

    #[must_use]
    pub fn extensions(mut self, extensions: Value) -> Self {
        self.extensions = Some(Arc::new(move |_| Box::pin(ready(Some(extensions.clone())))));
        self
    }

    #[must_use]
    pub fn extensions_resolver<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(PasskeyExtensionsInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<Value>> + Send + 'static,
    {
        self.extensions = Some(Arc::new(move |input| Box::pin(resolver(input))));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRegistrationUserInput {
    pub context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyExtensionsInput {
    pub context: Option<String>,
    /// Authenticated user id when generating session-scoped authentication options.
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AfterRegistrationVerificationInput {
    pub user: PasskeyRegistrationUser,
    pub client_data: Value,
    pub context: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AfterAuthenticationVerificationInput {
    pub credential_id: String,
    pub client_data: Value,
}
