use std::sync::OnceLock;

use base64::Engine;
use openauth_core::api::{json_response, ApiResponse};
use openauth_core::auth::trusted_origins::OriginMatchSettings;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMetadata {
    pub sha256_fingerprint: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub parse_error: Option<String>,
}

pub fn client_id_last_four(client_id: &str) -> String {
    let char_count = client_id.chars().count();
    if char_count <= 4 {
        return "****".to_owned();
    }
    let suffix = client_id
        .chars()
        .skip(char_count.saturating_sub(4))
        .collect::<String>();
    format!("****{suffix}")
}

pub fn certificate_metadata(cert: &str) -> CertificateMetadata {
    let normalized = normalize_certificate(cert);
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&normalized) else {
        return CertificateMetadata {
            sha256_fingerprint: String::new(),
            not_before: None,
            not_after: None,
            public_key_algorithm: None,
            parse_error: Some("Failed to parse certificate".to_owned()),
        };
    };
    let fingerprint = sha256_hex(&der);
    let Ok((_, certificate)) = X509Certificate::from_der(&der) else {
        return CertificateMetadata {
            sha256_fingerprint: fingerprint,
            not_before: None,
            not_after: None,
            public_key_algorithm: None,
            parse_error: Some("Failed to parse certificate".to_owned()),
        };
    };
    let validity = certificate.validity();
    CertificateMetadata {
        sha256_fingerprint: fingerprint,
        not_before: validity.not_before.to_datetime().format(&Rfc3339).ok(),
        not_after: validity.not_after.to_datetime().format(&Rfc3339).ok(),
        public_key_algorithm: certificate
            .public_key()
            .parsed()
            .ok()
            .map(public_key_algorithm),
        parse_error: None,
    }
}

pub fn json<T: Serialize>(
    status: http::StatusCode,
    body: &T,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(status, body, Vec::new())
}

pub(crate) fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(reqwest::Client::new)
}

pub fn safe_redirect_url(context: &AuthContext, value: &str) -> Option<String> {
    if value.is_empty() || value.trim() != value {
        return None;
    }
    let settings = Some(OriginMatchSettings {
        allow_relative_paths: true,
    });
    if !context.is_trusted_origin(value, settings) || is_sso_redirect_loop(value) {
        return None;
    }
    Some(value.to_owned())
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(hasher.finalize())
}

fn normalize_certificate(cert: &str) -> String {
    cert.lines()
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .flat_map(|line| line.chars())
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn public_key_algorithm(public_key: PublicKey<'_>) -> String {
    match public_key {
        PublicKey::RSA(key) => format!("RSA-{}", key.key_size()),
        PublicKey::EC(key) => format!("EC-{}", key.key_size()),
        PublicKey::DSA(key) => format!("DSA-{}", key.len() * 8),
        PublicKey::GostR3410(key) => format!("GOST-R3410-{}", key.len() * 8),
        PublicKey::GostR3410_2012(key) => format!("GOST-R3410-2012-{}", key.len() * 8),
        PublicKey::Unknown(_) => "unknown".to_owned(),
    }
}

fn is_sso_redirect_loop(value: &str) -> bool {
    let path = if value.starts_with('/') {
        value.split('?').next().unwrap_or(value).to_owned()
    } else {
        match url::Url::parse(value) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => url.path().to_owned(),
            _ => return true,
        }
    };
    let path = path.trim_end_matches('/');
    path == "/sign-in/sso"
        || path == "/sso/callback"
        || path.starts_with("/sso/callback/")
        || path == "/sso/saml2/callback"
        || path.starts_with("/sso/saml2/callback/")
        || path == "/sso/saml2/sp/acs"
        || path.starts_with("/sso/saml2/sp/acs/")
}
