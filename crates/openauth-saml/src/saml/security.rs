use openauth_core::error::OpenAuthError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use time::{Duration, OffsetDateTime};

use super::xml::{local_name, validate_saml_xml};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlConditions {
    pub not_before: Option<String>,
    pub not_on_or_after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampValidationOptions {
    pub clock_skew: Duration,
    pub require_timestamps: bool,
}

impl Default for TimestampValidationOptions {
    fn default() -> Self {
        Self {
            clock_skew: Duration::minutes(5),
            require_timestamps: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SamlSecurityError {
    #[error("SAML assertion missing required timestamp conditions")]
    MissingTimestampConditions,
    #[error("SAML assertion has invalid NotBefore timestamp")]
    InvalidNotBefore,
    #[error("SAML assertion has invalid NotOnOrAfter timestamp")]
    InvalidNotOnOrAfter,
    #[error("SAML assertion is not yet valid")]
    NotYetValid,
    #[error("SAML assertion has expired")]
    Expired,
    #[error("SAML signature algorithm not recognized: {0}")]
    UnknownSignatureAlgorithm(String),
    #[error("SAML digest algorithm not recognized: {0}")]
    UnknownDigestAlgorithm(String),
    #[error("SAML signature algorithm is deprecated: {0}")]
    DeprecatedSignatureAlgorithm(String),
    #[error("SAML digest algorithm is deprecated: {0}")]
    DeprecatedDigestAlgorithm(String),
    #[error("SAML signature algorithm not in allow-list: {0}")]
    SignatureAlgorithmNotAllowed(String),
    #[error("SAML digest algorithm not in allow-list: {0}")]
    DigestAlgorithmNotAllowed(String),
    #[error("SAML key encryption algorithm not recognized: {0}")]
    UnknownKeyEncryptionAlgorithm(String),
    #[error("SAML data encryption algorithm not recognized: {0}")]
    UnknownDataEncryptionAlgorithm(String),
    #[error("SAML key encryption algorithm is deprecated: {0}")]
    DeprecatedKeyEncryptionAlgorithm(String),
    #[error("SAML data encryption algorithm is deprecated: {0}")]
    DeprecatedDataEncryptionAlgorithm(String),
    #[error("SAML key encryption algorithm not in allow-list: {0}")]
    KeyEncryptionAlgorithmNotAllowed(String),
    #[error("SAML data encryption algorithm not in allow-list: {0}")]
    DataEncryptionAlgorithmNotAllowed(String),
}

pub fn validate_saml_timestamp(
    conditions: Option<&SamlConditions>,
    options: TimestampValidationOptions,
) -> Result<(), SamlSecurityError> {
    let has_timestamps = conditions.is_some_and(|conditions| {
        conditions.not_before.is_some() || conditions.not_on_or_after.is_some()
    });
    if !has_timestamps {
        return if options.require_timestamps {
            Err(SamlSecurityError::MissingTimestampConditions)
        } else {
            Ok(())
        };
    }

    let Some(conditions) = conditions else {
        return if options.require_timestamps {
            Err(SamlSecurityError::MissingTimestampConditions)
        } else {
            Ok(())
        };
    };
    let now = OffsetDateTime::now_utc();

    if let Some(not_before) = &conditions.not_before {
        let parsed =
            OffsetDateTime::parse(not_before, &time::format_description::well_known::Rfc3339)
                .map_err(|_| SamlSecurityError::InvalidNotBefore)?;
        if now < parsed - options.clock_skew {
            return Err(SamlSecurityError::NotYetValid);
        }
    }

    if let Some(not_on_or_after) = &conditions.not_on_or_after {
        let parsed = OffsetDateTime::parse(
            not_on_or_after,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| SamlSecurityError::InvalidNotOnOrAfter)?;
        if now > parsed + options.clock_skew {
            return Err(SamlSecurityError::Expired);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeprecatedAlgorithmBehavior {
    Reject,
    Warn,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaSha1,
    RsaSha256,
    RsaSha384,
    RsaSha512,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
}

impl SignatureAlgorithm {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::RsaSha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        }
    }
}

pub fn validate_saml_config_algorithms(
    signature_algorithm: Option<&str>,
    digest_algorithm: Option<&str>,
) -> Result<(), SamlSecurityError> {
    validate_saml_config_algorithms_with_policy(
        signature_algorithm,
        digest_algorithm,
        DeprecatedAlgorithmBehavior::Warn,
        None,
        None,
    )
}

pub fn validate_saml_config_algorithms_with_policy(
    signature_algorithm: Option<&str>,
    digest_algorithm: Option<&str>,
    on_deprecated: DeprecatedAlgorithmBehavior,
    allowed_signature_algorithms: Option<&[String]>,
    allowed_digest_algorithms: Option<&[String]>,
) -> Result<(), SamlSecurityError> {
    if let Some(algorithm) = signature_algorithm {
        let normalized = normalize_signature_algorithm(algorithm);
        if let Some(allowed) = allowed_signature_algorithms {
            let is_allowed = allowed
                .iter()
                .map(|algorithm| normalize_signature_algorithm(algorithm))
                .any(|allowed| allowed == normalized);
            if !is_allowed {
                return Err(SamlSecurityError::SignatureAlgorithmNotAllowed(
                    algorithm.to_owned(),
                ));
            }
        } else if is_deprecated_signature_algorithm(&normalized)
            && on_deprecated == DeprecatedAlgorithmBehavior::Reject
        {
            return Err(SamlSecurityError::DeprecatedSignatureAlgorithm(
                algorithm.to_owned(),
            ));
        } else if !is_known_signature_algorithm(&normalized) {
            return Err(SamlSecurityError::UnknownSignatureAlgorithm(
                algorithm.to_owned(),
            ));
        }
    }
    if let Some(algorithm) = digest_algorithm {
        let normalized = normalize_digest_algorithm(algorithm);
        if let Some(allowed) = allowed_digest_algorithms {
            let is_allowed = allowed
                .iter()
                .map(|algorithm| normalize_digest_algorithm(algorithm))
                .any(|allowed| allowed == normalized);
            if !is_allowed {
                return Err(SamlSecurityError::DigestAlgorithmNotAllowed(
                    algorithm.to_owned(),
                ));
            }
        } else if is_deprecated_digest_algorithm(&normalized)
            && on_deprecated == DeprecatedAlgorithmBehavior::Reject
        {
            return Err(SamlSecurityError::DeprecatedDigestAlgorithm(
                algorithm.to_owned(),
            ));
        } else if !is_known_digest_algorithm(&normalized) {
            return Err(SamlSecurityError::UnknownDigestAlgorithm(
                algorithm.to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SamlRuntimeAlgorithms {
    pub signature_algorithms: Vec<String>,
    pub digest_algorithms: Vec<String>,
    pub key_encryption_algorithms: Vec<String>,
    pub data_encryption_algorithms: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamlRuntimeAlgorithmPolicy<'a> {
    pub on_deprecated: DeprecatedAlgorithmBehavior,
    pub allowed_signature_algorithms: Option<&'a [String]>,
    pub allowed_digest_algorithms: Option<&'a [String]>,
    pub allowed_key_encryption_algorithms: Option<&'a [String]>,
    pub allowed_data_encryption_algorithms: Option<&'a [String]>,
}

impl Default for SamlRuntimeAlgorithmPolicy<'_> {
    fn default() -> Self {
        Self {
            on_deprecated: DeprecatedAlgorithmBehavior::Warn,
            allowed_signature_algorithms: None,
            allowed_digest_algorithms: None,
            allowed_key_encryption_algorithms: None,
            allowed_data_encryption_algorithms: None,
        }
    }
}

pub fn collect_saml_runtime_algorithms(xml: &str) -> Result<SamlRuntimeAlgorithms, OpenAuthError> {
    validate_saml_xml(xml)?;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::new();
    let mut algorithms = SamlRuntimeAlgorithms::default();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name().as_ref())?;
                collect_algorithm(&reader, &element, &name, &stack, &mut algorithms)?;
                stack.push(name);
            }
            Ok(Event::Empty(element)) => {
                let name = local_name(element.name().as_ref())?;
                collect_algorithm(&reader, &element, &name, &stack, &mut algorithms)?;
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            Ok(_) => {}
        }
    }

    Ok(algorithms)
}

pub fn validate_saml_runtime_algorithms(
    algorithms: &SamlRuntimeAlgorithms,
    policy: SamlRuntimeAlgorithmPolicy<'_>,
) -> Result<(), SamlSecurityError> {
    for algorithm in &algorithms.signature_algorithms {
        validate_signature_algorithm(
            algorithm,
            policy.on_deprecated,
            policy.allowed_signature_algorithms,
        )?;
    }
    for algorithm in &algorithms.digest_algorithms {
        validate_digest_algorithm(
            algorithm,
            policy.on_deprecated,
            policy.allowed_digest_algorithms,
        )?;
    }
    for algorithm in &algorithms.key_encryption_algorithms {
        validate_key_encryption_algorithm(
            algorithm,
            policy.on_deprecated,
            policy.allowed_key_encryption_algorithms,
        )?;
    }
    for algorithm in &algorithms.data_encryption_algorithms {
        validate_data_encryption_algorithm(
            algorithm,
            policy.on_deprecated,
            policy.allowed_data_encryption_algorithms,
        )?;
    }
    Ok(())
}

fn collect_algorithm(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &str,
    stack: &[String],
    algorithms: &mut SamlRuntimeAlgorithms,
) -> Result<(), OpenAuthError> {
    let Some(algorithm) = attr(reader, element, "Algorithm")? else {
        return Ok(());
    };
    match name {
        "SignatureMethod" => algorithms.signature_algorithms.push(algorithm),
        "DigestMethod" => algorithms.digest_algorithms.push(algorithm),
        "EncryptionMethod" if stack.iter().any(|item| item == "EncryptedKey") => {
            algorithms.key_encryption_algorithms.push(algorithm);
        }
        "EncryptionMethod" if stack.iter().any(|item| item == "EncryptedData") => {
            algorithms.data_encryption_algorithms.push(algorithm);
        }
        _ => {}
    }
    Ok(())
}

fn attr(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &str,
) -> Result<Option<String>, OpenAuthError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| OpenAuthError::Api(error.to_string()))?;
        if local_name(attribute.key.as_ref())? == name {
            return attribute
                .decode_and_unescape_value(reader.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| OpenAuthError::Api(error.to_string()));
        }
    }
    Ok(None)
}

fn normalize_signature_algorithm(algorithm: &str) -> String {
    match algorithm.to_ascii_lowercase().as_str() {
        "sha1" | "rsa-sha1" => SignatureAlgorithm::RsaSha1.as_uri().to_owned(),
        "sha256" | "rsa-sha256" => SignatureAlgorithm::RsaSha256.as_uri().to_owned(),
        "sha384" | "rsa-sha384" => SignatureAlgorithm::RsaSha384.as_uri().to_owned(),
        "sha512" | "rsa-sha512" => SignatureAlgorithm::RsaSha512.as_uri().to_owned(),
        "ecdsa-sha256" => SignatureAlgorithm::EcdsaSha256.as_uri().to_owned(),
        "ecdsa-sha384" => SignatureAlgorithm::EcdsaSha384.as_uri().to_owned(),
        "ecdsa-sha512" => SignatureAlgorithm::EcdsaSha512.as_uri().to_owned(),
        _ => algorithm.to_owned(),
    }
}

fn normalize_digest_algorithm(algorithm: &str) -> String {
    match algorithm.to_ascii_lowercase().as_str() {
        "sha1" => DigestAlgorithm::Sha1.as_uri().to_owned(),
        "sha256" => DigestAlgorithm::Sha256.as_uri().to_owned(),
        "sha384" => DigestAlgorithm::Sha384.as_uri().to_owned(),
        "sha512" => DigestAlgorithm::Sha512.as_uri().to_owned(),
        _ => algorithm.to_owned(),
    }
}

fn normalize_key_encryption_algorithm(algorithm: &str) -> String {
    match algorithm.to_ascii_lowercase().as_str() {
        "rsa-1_5" | "rsa1_5" => KeyEncryptionAlgorithm::Rsa15.as_uri().to_owned(),
        "rsa-oaep" | "rsa-oaep-mgf1p" => KeyEncryptionAlgorithm::RsaOaep.as_uri().to_owned(),
        "rsa-oaep-sha256" => KeyEncryptionAlgorithm::RsaOaepSha256.as_uri().to_owned(),
        _ => algorithm.to_owned(),
    }
}

fn normalize_data_encryption_algorithm(algorithm: &str) -> String {
    match algorithm.to_ascii_lowercase().as_str() {
        "tripledes-cbc" | "3des-cbc" => DataEncryptionAlgorithm::TripleDesCbc.as_uri().to_owned(),
        "aes128-cbc" => DataEncryptionAlgorithm::Aes128Cbc.as_uri().to_owned(),
        "aes192-cbc" => DataEncryptionAlgorithm::Aes192Cbc.as_uri().to_owned(),
        "aes256-cbc" => DataEncryptionAlgorithm::Aes256Cbc.as_uri().to_owned(),
        "aes128-gcm" => DataEncryptionAlgorithm::Aes128Gcm.as_uri().to_owned(),
        "aes192-gcm" => DataEncryptionAlgorithm::Aes192Gcm.as_uri().to_owned(),
        "aes256-gcm" => DataEncryptionAlgorithm::Aes256Gcm.as_uri().to_owned(),
        _ => algorithm.to_owned(),
    }
}

fn validate_signature_algorithm(
    algorithm: &str,
    on_deprecated: DeprecatedAlgorithmBehavior,
    allowed: Option<&[String]>,
) -> Result<(), SamlSecurityError> {
    let normalized = normalize_signature_algorithm(algorithm);
    if let Some(allowed) = allowed {
        let is_allowed = allowed
            .iter()
            .map(|algorithm| normalize_signature_algorithm(algorithm))
            .any(|allowed| allowed == normalized);
        if !is_allowed {
            return Err(SamlSecurityError::SignatureAlgorithmNotAllowed(
                algorithm.to_owned(),
            ));
        }
    } else if is_deprecated_signature_algorithm(&normalized)
        && on_deprecated == DeprecatedAlgorithmBehavior::Reject
    {
        return Err(SamlSecurityError::DeprecatedSignatureAlgorithm(
            algorithm.to_owned(),
        ));
    } else if !is_known_signature_algorithm(&normalized) {
        return Err(SamlSecurityError::UnknownSignatureAlgorithm(
            algorithm.to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest_algorithm(
    algorithm: &str,
    on_deprecated: DeprecatedAlgorithmBehavior,
    allowed: Option<&[String]>,
) -> Result<(), SamlSecurityError> {
    let normalized = normalize_digest_algorithm(algorithm);
    if let Some(allowed) = allowed {
        let is_allowed = allowed
            .iter()
            .map(|algorithm| normalize_digest_algorithm(algorithm))
            .any(|allowed| allowed == normalized);
        if !is_allowed {
            return Err(SamlSecurityError::DigestAlgorithmNotAllowed(
                algorithm.to_owned(),
            ));
        }
    } else if is_deprecated_digest_algorithm(&normalized)
        && on_deprecated == DeprecatedAlgorithmBehavior::Reject
    {
        return Err(SamlSecurityError::DeprecatedDigestAlgorithm(
            algorithm.to_owned(),
        ));
    } else if !is_known_digest_algorithm(&normalized) {
        return Err(SamlSecurityError::UnknownDigestAlgorithm(
            algorithm.to_owned(),
        ));
    }
    Ok(())
}

fn is_known_signature_algorithm(algorithm: &str) -> bool {
    [
        SignatureAlgorithm::RsaSha1,
        SignatureAlgorithm::RsaSha256,
        SignatureAlgorithm::RsaSha384,
        SignatureAlgorithm::RsaSha512,
        SignatureAlgorithm::EcdsaSha256,
        SignatureAlgorithm::EcdsaSha384,
        SignatureAlgorithm::EcdsaSha512,
    ]
    .into_iter()
    .any(|known| known.as_uri() == algorithm)
}

fn is_deprecated_signature_algorithm(algorithm: &str) -> bool {
    SignatureAlgorithm::RsaSha1.as_uri() == algorithm
}

fn is_known_digest_algorithm(algorithm: &str) -> bool {
    [
        DigestAlgorithm::Sha1,
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ]
    .into_iter()
    .any(|known| known.as_uri() == algorithm)
}

fn is_deprecated_digest_algorithm(algorithm: &str) -> bool {
    DigestAlgorithm::Sha1.as_uri() == algorithm
}

fn validate_key_encryption_algorithm(
    algorithm: &str,
    on_deprecated: DeprecatedAlgorithmBehavior,
    allowed: Option<&[String]>,
) -> Result<(), SamlSecurityError> {
    let normalized = normalize_key_encryption_algorithm(algorithm);
    if let Some(allowed) = allowed {
        let is_allowed = allowed
            .iter()
            .map(|algorithm| normalize_key_encryption_algorithm(algorithm))
            .any(|allowed| allowed == normalized);
        if !is_allowed {
            return Err(SamlSecurityError::KeyEncryptionAlgorithmNotAllowed(
                algorithm.to_owned(),
            ));
        }
    } else if is_deprecated_key_encryption_algorithm(&normalized)
        && on_deprecated == DeprecatedAlgorithmBehavior::Reject
    {
        return Err(SamlSecurityError::DeprecatedKeyEncryptionAlgorithm(
            algorithm.to_owned(),
        ));
    } else if !is_known_key_encryption_algorithm(&normalized) {
        return Err(SamlSecurityError::UnknownKeyEncryptionAlgorithm(
            algorithm.to_owned(),
        ));
    }
    Ok(())
}

fn validate_data_encryption_algorithm(
    algorithm: &str,
    on_deprecated: DeprecatedAlgorithmBehavior,
    allowed: Option<&[String]>,
) -> Result<(), SamlSecurityError> {
    let normalized = normalize_data_encryption_algorithm(algorithm);
    if let Some(allowed) = allowed {
        let is_allowed = allowed
            .iter()
            .map(|algorithm| normalize_data_encryption_algorithm(algorithm))
            .any(|allowed| allowed == normalized);
        if !is_allowed {
            return Err(SamlSecurityError::DataEncryptionAlgorithmNotAllowed(
                algorithm.to_owned(),
            ));
        }
    } else if is_deprecated_data_encryption_algorithm(&normalized)
        && on_deprecated == DeprecatedAlgorithmBehavior::Reject
    {
        return Err(SamlSecurityError::DeprecatedDataEncryptionAlgorithm(
            algorithm.to_owned(),
        ));
    } else if !is_known_data_encryption_algorithm(&normalized) {
        return Err(SamlSecurityError::UnknownDataEncryptionAlgorithm(
            algorithm.to_owned(),
        ));
    }
    Ok(())
}

fn is_known_key_encryption_algorithm(algorithm: &str) -> bool {
    [
        KeyEncryptionAlgorithm::Rsa15,
        KeyEncryptionAlgorithm::RsaOaep,
        KeyEncryptionAlgorithm::RsaOaepSha256,
    ]
    .into_iter()
    .any(|known| known.as_uri() == algorithm)
}

fn is_deprecated_key_encryption_algorithm(algorithm: &str) -> bool {
    KeyEncryptionAlgorithm::Rsa15.as_uri() == algorithm
}

fn is_known_data_encryption_algorithm(algorithm: &str) -> bool {
    [
        DataEncryptionAlgorithm::TripleDesCbc,
        DataEncryptionAlgorithm::Aes128Cbc,
        DataEncryptionAlgorithm::Aes192Cbc,
        DataEncryptionAlgorithm::Aes256Cbc,
        DataEncryptionAlgorithm::Aes128Gcm,
        DataEncryptionAlgorithm::Aes192Gcm,
        DataEncryptionAlgorithm::Aes256Gcm,
    ]
    .into_iter()
    .any(|known| known.as_uri() == algorithm)
}

fn is_deprecated_data_encryption_algorithm(algorithm: &str) -> bool {
    DataEncryptionAlgorithm::TripleDesCbc.as_uri() == algorithm
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEncryptionAlgorithm {
    Rsa15,
    RsaOaep,
    RsaOaepSha256,
}

impl KeyEncryptionAlgorithm {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::Rsa15 => "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
            Self::RsaOaep => "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            Self::RsaOaepSha256 => "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEncryptionAlgorithm {
    TripleDesCbc,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

impl DataEncryptionAlgorithm {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::TripleDesCbc => "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
            Self::Aes128Cbc => "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            Self::Aes192Cbc => "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
            Self::Aes256Cbc => "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            Self::Aes128Gcm => "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            Self::Aes192Gcm => "http://www.w3.org/2009/xmlenc11#aes192-gcm",
            Self::Aes256Gcm => "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        }
    }
}
