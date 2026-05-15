use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::context::AuthContext;
use openauth_core::db::{Session, User};
use openauth_core::error::OpenAuthError;

use super::{Jwk, JwkAlgorithm, JwtClaims};

pub type JwtClaimsFuture<'a> =
    Pin<Box<dyn Future<Output = Result<JwtClaims, OpenAuthError>> + Send + 'a>>;
pub type JwtStringFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send + 'a>>;
pub type JwtJwksFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<Jwk>, OpenAuthError>> + Send + 'a>>;
pub type JwtJwkFuture<'a> = Pin<Box<dyn Future<Output = Result<Jwk, OpenAuthError>> + Send + 'a>>;

pub type JwtDefinePayloadHandler =
    Arc<dyn for<'a> Fn(&'a JwtSessionContext) -> JwtClaimsFuture<'a> + Send + Sync>;
pub type JwtGetSubjectHandler =
    Arc<dyn for<'a> Fn(&'a JwtSessionContext) -> JwtStringFuture<'a> + Send + Sync>;
pub type JwtSignHandler = Arc<dyn Fn(JwtClaims) -> JwtStringFuture<'static> + Send + Sync>;
pub type JwtGetJwksHandler =
    Arc<dyn for<'a> Fn(&'a AuthContext) -> JwtJwksFuture<'a> + Send + Sync>;
pub type JwtCreateJwkHandler =
    Arc<dyn for<'a> Fn(&'a AuthContext, Jwk) -> JwtJwkFuture<'a> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtSessionContext {
    pub session: Session,
    pub user: User,
}

#[derive(Clone, Default)]
pub struct JwtOptions {
    pub jwks: JwtJwksOptions,
    pub jwt: JwtSigningOptions,
    pub adapter: JwtAdapterOptions,
    pub disable_setting_jwt_header: bool,
}

#[derive(Debug, Clone)]
pub struct JwtJwksOptions {
    pub remote_url: Option<String>,
    pub key_pair_algorithm: Option<JwkAlgorithm>,
    pub rsa_modulus_length: Option<u32>,
    pub disable_private_key_encryption: bool,
    pub rotation_interval: Option<i64>,
    pub grace_period: i64,
    pub jwks_path: String,
}

impl Default for JwtJwksOptions {
    fn default() -> Self {
        Self {
            remote_url: None,
            key_pair_algorithm: Some(JwkAlgorithm::EdDsa),
            rsa_modulus_length: None,
            disable_private_key_encryption: false,
            rotation_interval: None,
            grace_period: 60 * 60 * 24 * 30,
            jwks_path: "/jwks".to_owned(),
        }
    }
}

#[derive(Clone, Default)]
pub struct JwtSigningOptions {
    pub issuer: Option<String>,
    pub audience: Option<Vec<String>>,
    pub expiration_time: Option<super::TimeInput>,
    pub define_payload: Option<JwtDefinePayloadHandler>,
    pub get_subject: Option<JwtGetSubjectHandler>,
    pub sign: Option<JwtSignHandler>,
}

impl fmt::Debug for JwtSigningOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtSigningOptions")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("expiration_time", &self.expiration_time)
            .field(
                "define_payload",
                &self.define_payload.as_ref().map(|_| "<define-payload>"),
            )
            .field(
                "get_subject",
                &self.get_subject.as_ref().map(|_| "<get-subject>"),
            )
            .field("sign", &self.sign.as_ref().map(|_| "<sign-handler>"))
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct JwtAdapterOptions {
    pub get_jwks: Option<JwtGetJwksHandler>,
    pub create_jwk: Option<JwtCreateJwkHandler>,
}

impl fmt::Debug for JwtAdapterOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtAdapterOptions")
            .field("get_jwks", &self.get_jwks.as_ref().map(|_| "<get-jwks>"))
            .field(
                "create_jwk",
                &self.create_jwk.as_ref().map(|_| "<create-jwk>"),
            )
            .finish()
    }
}

impl JwtOptions {
    pub fn validate(&self) -> Result<(), OpenAuthError> {
        if self.jwt.sign.is_some() && self.jwks.remote_url.is_none() {
            return Err(OpenAuthError::InvalidConfig(
                "options.jwks.remoteUrl must be set when using options.jwt.sign".to_owned(),
            ));
        }
        if self.jwks.remote_url.is_some() && self.jwks.key_pair_algorithm.is_none() {
            return Err(OpenAuthError::InvalidConfig(
                "options.jwks.keyPairConfig.alg must be specified when using remoteUrl".to_owned(),
            ));
        }
        if let Some(modulus_length) = self.jwks.rsa_modulus_length {
            if modulus_length < 2048 {
                return Err(OpenAuthError::InvalidConfig(
                    "options.jwks.keyPairConfig.modulusLength must be at least 2048".to_owned(),
                ));
            }
        }
        let path = &self.jwks.jwks_path;
        if path.is_empty() || !path.starts_with('/') || path.contains("..") {
            return Err(OpenAuthError::InvalidConfig(
                "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn algorithm(&self) -> JwkAlgorithm {
        self.jwks.key_pair_algorithm.unwrap_or(JwkAlgorithm::EdDsa)
    }
}
