use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::schema::SiweSchemaOptions;

type BoxFuture<T> = Pin<Box<dyn Future<Output = Result<T, RustAuthError>> + Send>>;

pub type GetNonce = Arc<dyn Fn() -> BoxFuture<String> + Send + Sync>;
pub type VerifyMessage = Arc<dyn Fn(SiweVerifyMessageArgs) -> BoxFuture<bool> + Send + Sync>;
pub type EnsLookup = Arc<dyn Fn(EnsLookupArgs) -> BoxFuture<Option<EnsLookupResult>> + Send + Sync>;

#[derive(Clone)]
pub struct SiweOptions {
    pub(crate) domain: String,
    pub(crate) email_domain_name: Option<String>,
    pub(crate) anonymous: bool,
    pub(crate) get_nonce: GetNonce,
    pub(crate) verify_message: VerifyMessage,
    pub(crate) ens_lookup: Option<EnsLookup>,
    pub(crate) schema: SiweSchemaOptions,
}

impl SiweOptions {
    pub fn new<G, GFut, V, VFut>(domain: impl Into<String>, get_nonce: G, verify_message: V) -> Self
    where
        G: Fn() -> GFut + Send + Sync + 'static,
        GFut: Future<Output = Result<String, RustAuthError>> + Send + 'static,
        V: Fn(SiweVerifyMessageArgs) -> VFut + Send + Sync + 'static,
        VFut: Future<Output = Result<bool, RustAuthError>> + Send + 'static,
    {
        Self {
            domain: domain.into(),
            email_domain_name: None,
            anonymous: true,
            get_nonce: Arc::new(move || Box::pin(get_nonce())),
            verify_message: Arc::new(move |args| Box::pin(verify_message(args))),
            ens_lookup: None,
            schema: SiweSchemaOptions::new(),
        }
    }

    #[must_use]
    pub fn builder() -> SiweOptionsBuilder {
        SiweOptionsBuilder::default()
    }

    #[must_use]
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(domain.into());
        self
    }

    #[must_use]
    pub fn anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = anonymous;
        self
    }

    #[must_use]
    pub fn ens_lookup<E, EFut>(mut self, ens_lookup: E) -> Self
    where
        E: Fn(EnsLookupArgs) -> EFut + Send + Sync + 'static,
        EFut: Future<Output = Result<Option<EnsLookupResult>, RustAuthError>> + Send + 'static,
    {
        self.ens_lookup = Some(Arc::new(move |args| Box::pin(ens_lookup(args))));
        self
    }

    #[must_use]
    pub fn schema(mut self, schema: SiweSchemaOptions) -> Self {
        self.schema = schema;
        self
    }

    pub(crate) fn schema_options(&self) -> &SiweSchemaOptions {
        &self.schema
    }

    pub(crate) fn validate(&self) -> Result<(), RustAuthError> {
        if self.domain.trim().is_empty() {
            return Err(RustAuthError::InvalidConfig(
                "siwe domain cannot be empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn metadata(&self) -> serde_json::Value {
        let mut metadata = serde_json::json!({
            "domain": self.domain,
            "anonymous": self.anonymous,
            "schema": self.schema.metadata(),
        });
        if let Some(email_domain_name) = &self.email_domain_name {
            metadata["emailDomainName"] = serde_json::Value::String(email_domain_name.clone());
        }
        metadata
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletAddress {
    pub id: String,
    pub user_id: String,
    pub address: String,
    pub chain_id: i64,
    pub is_primary: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiweVerifyMessageArgs {
    pub message: String,
    pub signature: String,
    pub address: String,
    pub chain_id: i64,
    pub cacao: Cacao,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cacao {
    pub h: CacaoHeader,
    pub p: CacaoPayload,
    pub s: CacaoSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacaoHeader {
    pub t: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacaoPayload {
    pub domain: String,
    pub aud: String,
    pub nonce: String,
    pub iss: String,
    pub version: Option<String>,
    pub iat: Option<String>,
    pub nbf: Option<String>,
    pub exp: Option<String>,
    pub statement: Option<String>,
    pub request_id: Option<String>,
    pub resources: Option<Vec<String>>,
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacaoSignature {
    pub t: String,
    pub s: String,
    pub m: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsLookupArgs {
    pub wallet_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsLookupResult {
    pub name: String,
    pub avatar: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NonceRequest {
    pub wallet_address: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyRequest {
    pub message: String,
    pub signature: String,
    pub wallet_address: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: i64,
    pub email: Option<String>,
}

fn default_chain_id() -> i64 {
    1
}

#[derive(Clone, Default)]
pub struct SiweOptionsBuilder {
    domain: Option<String>,
    email_domain_name: Option<Option<String>>,
    anonymous: Option<bool>,
    get_nonce: Option<GetNonce>,
    verify_message: Option<VerifyMessage>,
    ens_lookup: Option<EnsLookup>,
    schema: Option<SiweSchemaOptions>,
}

impl SiweOptionsBuilder {
    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    #[must_use]
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(Some(domain.into()));
        self
    }

    #[must_use]
    pub fn anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = Some(anonymous);
        self
    }

    #[must_use]
    pub fn get_nonce(mut self, get_nonce: GetNonce) -> Self {
        self.get_nonce = Some(get_nonce);
        self
    }

    #[must_use]
    pub fn verify_message(mut self, verify_message: VerifyMessage) -> Self {
        self.verify_message = Some(verify_message);
        self
    }

    #[must_use]
    pub fn ens_lookup(mut self, ens_lookup: EnsLookup) -> Self {
        self.ens_lookup = Some(ens_lookup);
        self
    }

    #[must_use]
    pub fn schema(mut self, schema: SiweSchemaOptions) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn build(self) -> Result<SiweOptions, RustAuthError> {
        let domain = self
            .domain
            .ok_or_else(|| RustAuthError::InvalidConfig("siwe domain is required".to_owned()))?;
        let get_nonce = self.get_nonce.ok_or_else(|| {
            RustAuthError::InvalidConfig("siwe get_nonce callback is required".to_owned())
        })?;
        let verify_message = self.verify_message.ok_or_else(|| {
            RustAuthError::InvalidConfig("siwe verify_message callback is required".to_owned())
        })?;
        let options = SiweOptions {
            domain,
            email_domain_name: self.email_domain_name.unwrap_or(None),
            anonymous: self.anonymous.unwrap_or(true),
            get_nonce,
            verify_message,
            ens_lookup: self.ens_lookup,
            schema: self.schema.unwrap_or_default(),
        };
        options.validate()?;
        Ok(options)
    }
}
