use std::collections::BTreeMap;

use rustauth_core::secret::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// SAML configuration for an enterprise SSO provider.
pub struct SamlProviderConfig {
    /// Service provider issuer/entity id expected by the IdP.
    pub issuer: String,
    #[serde(default)]
    /// IdP SSO entry point for AuthnRequest redirects.
    pub entry_point: String,
    /// IdP signing certificate, either PEM or base64 body.
    pub cert: String,
    /// RustAuth callback URL used after SAML login.
    pub callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit assertion consumer service URL.
    pub acs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Expected SAML audience. Defaults to issuer semantics when omitted.
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Parsed or configured IdP metadata.
    pub idp_metadata: Option<SamlIdpMetadata>,
    /// Service provider metadata configuration.
    pub sp_metadata: SamlSpMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Provider attribute mapping.
    pub mapping: Option<SamlMapping>,
    /// Require valid XMLDSig over the SAML Assertion.
    #[serde(default = "default_want_assertions_signed")]
    pub want_assertions_signed: bool,
    /// Sign outbound AuthnRequest messages.
    pub authn_requests_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Signature algorithm URI or short name for outbound signed requests.
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Digest algorithm URI or short name for outbound signed requests.
    pub digest_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// SAML NameID format requested from the IdP.
    pub identifier_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Service provider signing private key. Debug output is redacted.
    pub private_key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Service provider decryption private key for encrypted assertions.
    pub decryption_pvk: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Additional AuthnRequest parameters sent to the IdP.
    pub additional_params: Option<BTreeMap<String, serde_json::Value>>,
}

/// Backward-compatible SAML config alias.
pub type SamlConfig = SamlProviderConfig;

const fn default_want_assertions_signed() -> bool {
    true
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// IdP metadata fields accepted by SAML provider configuration.
pub struct SamlIdpMetadata {
    pub metadata: Option<String>,
    #[serde(rename = "entityID", alias = "entityId")]
    pub entity_id: Option<String>,
    #[serde(rename = "entityURL", alias = "entityUrl")]
    pub entity_url: Option<String>,
    #[serde(rename = "redirectURL", alias = "redirectUrl")]
    pub redirect_url: Option<String>,
    pub cert: Option<String>,
    pub private_key: Option<SecretString>,
    pub private_key_pass: Option<SecretString>,
    pub is_assertion_encrypted: Option<bool>,
    pub enc_private_key: Option<SecretString>,
    pub enc_private_key_pass: Option<SecretString>,
    pub single_sign_on_service: Option<Vec<SamlService>>,
    pub single_logout_service: Option<Vec<SamlService>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// SAML metadata service endpoint.
pub struct SamlService {
    #[serde(rename = "Binding")]
    pub binding: String,
    #[serde(rename = "Location")]
    pub location: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Service provider metadata overrides.
pub struct SamlSpMetadata {
    pub metadata: Option<String>,
    #[serde(rename = "entityID", alias = "entityId")]
    pub entity_id: Option<String>,
    pub binding: Option<String>,
    pub private_key: Option<SecretString>,
    pub private_key_pass: Option<SecretString>,
    pub is_assertion_encrypted: Option<bool>,
    pub enc_private_key: Option<SecretString>,
    pub enc_private_key_pass: Option<SecretString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Mapping from SAML attributes to RustAuth profile fields.
pub struct SamlMapping {
    pub id: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<String>,
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub extra_fields: Option<BTreeMap<String, String>>,
}
