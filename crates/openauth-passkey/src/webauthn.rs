use base64::Engine;
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

use webauthn_rs::prelude::{
    AttestationFormat, AttestationMetadata, COSEAlgorithm, COSEKey, COSEKeyType,
    CreationChallengeResponse, Credential, CredentialID, ECDSACurve, EDDSACurve, ParsedAttestation,
    Passkey, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AuthenticationState, AuthenticatorTransport,
    RegisteredExtensions, RegistrationState, RequestAuthenticationExtensions,
    RequestRegistrationExtensions, UserVerificationPolicy,
};
use webauthn_rs_core::WebauthnCore;

use crate::options::{
    PasskeyRegistrationUser, RegistrationWebAuthnOptions, UserVerificationRequirement,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyRegistrationStart {
    pub options: Value,
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyAuthenticationStart {
    pub options: Value,
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedPasskeyCredential {
    pub credential_id: String,
    pub public_key: String,
    pub counter: u32,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
    pub credential: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedAuthentication {
    pub credential: Option<Value>,
    pub new_counter: u32,
}

pub trait PasskeyWebAuthnBackend: Send + Sync {
    fn start_registration(
        &self,
        config: WebAuthnConfig,
        user: &PasskeyRegistrationUser,
        exclude_credentials: Vec<Value>,
        options: RegistrationWebAuthnOptions,
    ) -> Result<PasskeyRegistrationStart, OpenAuthError>;

    fn finish_registration(
        &self,
        config: WebAuthnConfig,
        response: Value,
        state: Value,
    ) -> Result<VerifiedPasskeyCredential, OpenAuthError> {
        let _ = (config, response, state);
        Err(OpenAuthError::Api(
            "passkey registration verification is not implemented".to_owned(),
        ))
    }

    fn start_authentication(
        &self,
        config: WebAuthnConfig,
        credentials: Vec<Value>,
        extensions: Option<Value>,
    ) -> Result<PasskeyAuthenticationStart, OpenAuthError>;

    fn finish_authentication(
        &self,
        config: WebAuthnConfig,
        response: Value,
        state: Value,
        credential: Option<Value>,
    ) -> Result<VerifiedAuthentication, OpenAuthError> {
        let _ = (config, response, state, credential);
        Err(OpenAuthError::Api(
            "passkey authentication verification is not implemented".to_owned(),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RealPasskeyWebAuthnBackend;

impl PasskeyWebAuthnBackend for RealPasskeyWebAuthnBackend {
    fn start_registration(
        &self,
        config: WebAuthnConfig,
        user: &PasskeyRegistrationUser,
        exclude_credentials: Vec<Value>,
        request_options: RegistrationWebAuthnOptions,
    ) -> Result<PasskeyRegistrationStart, OpenAuthError> {
        let core = core(&config)?;
        let exclude = exclude_credentials
            .into_iter()
            .map(parse_exclude_credential_id)
            .collect::<Result<Vec<_>, _>>()?;
        let user_id = Uuid::new_v4();
        let display_name = user.display_name.as_deref().unwrap_or(&user.name);
        let policy =
            user_verification_policy(request_options.authenticator_selection.user_verification);
        let builder = core
            .new_challenge_register_builder(user_id.as_bytes(), &user.name, display_name)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?
            .attestation(AttestationConveyancePreference::None)
            .credential_algorithms(COSEAlgorithm::secure_algs())
            .require_resident_key(false)
            .authenticator_attachment(None)
            .user_verification_policy(policy)
            .reject_synchronised_authenticators(false)
            .exclude_credentials(Some(exclude))
            .hints(None)
            .extensions(Some(RequestRegistrationExtensions::default()));
        let (options, state) = core
            .generate_challenge_register(builder)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let mut options = option_value(options)?;
        apply_registration_request_options(&mut options, &request_options);
        Ok(PasskeyRegistrationStart {
            options,
            state: serde_json::to_value(state).map_err(json_error)?,
        })
    }

    fn finish_registration(
        &self,
        config: WebAuthnConfig,
        response: Value,
        state: Value,
    ) -> Result<VerifiedPasskeyCredential, OpenAuthError> {
        let core = core(&config)?;
        let response = serde_json::from_value::<RegisterPublicKeyCredential>(response)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let state = serde_json::from_value::<RegistrationState>(state).map_err(json_error)?;
        let credential = core
            .register_credential(&response, &state, None)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        credential_output(Passkey::from(credential))
    }

    fn start_authentication(
        &self,
        config: WebAuthnConfig,
        credentials: Vec<Value>,
        extensions: Option<Value>,
    ) -> Result<PasskeyAuthenticationStart, OpenAuthError> {
        let core = core(&config)?;
        if credentials.is_empty() {
            let builder = core
                .new_challenge_authenticate_builder(
                    Vec::new(),
                    Some(UserVerificationPolicy::Preferred),
                )
                .map_err(|error| OpenAuthError::Api(error.to_string()))?
                .extensions(Some(RequestAuthenticationExtensions {
                    appid: None,
                    uvm: Some(true),
                    hmac_get_secret: None,
                }))
                .allow_backup_eligible_upgrade(false);
            let (options, state) = core
                .generate_challenge_authenticate(builder)
                .map_err(|error| OpenAuthError::Api(error.to_string()))?;
            let mut options = auth_option_value(options)?;
            apply_authentication_request_options(&mut options, extensions);
            return Ok(PasskeyAuthenticationStart {
                options,
                state: serde_json::to_value(StoredAuthenticationState::Discoverable(state))
                    .map_err(json_error)?,
            });
        }
        let creds = credentials
            .into_iter()
            .map(|value| credential_value_to_passkey(value).map(Credential::from))
            .collect::<Result<Vec<_>, _>>()?;
        let builder = core
            .new_challenge_authenticate_builder(creds, Some(UserVerificationPolicy::Preferred))
            .map_err(|error| OpenAuthError::Api(error.to_string()))?
            .allow_backup_eligible_upgrade(true);
        let (options, state) = core
            .generate_challenge_authenticate(builder)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let mut options = auth_option_value(options)?;
        apply_authentication_request_options(&mut options, extensions);
        Ok(PasskeyAuthenticationStart {
            options,
            state: serde_json::to_value(StoredAuthenticationState::Passkey(state))
                .map_err(json_error)?,
        })
    }

    fn finish_authentication(
        &self,
        config: WebAuthnConfig,
        response: Value,
        state: Value,
        credential: Option<Value>,
    ) -> Result<VerifiedAuthentication, OpenAuthError> {
        let core = core(&config)?;
        let response = serde_json::from_value::<PublicKeyCredential>(response)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let state =
            serde_json::from_value::<StoredAuthenticationState>(state).map_err(json_error)?;
        let credential = credential.map(credential_value_to_passkey).transpose()?;
        let result = match state {
            StoredAuthenticationState::Passkey(state) => core
                .authenticate_credential(&response, &state)
                .map_err(|error| OpenAuthError::Api(error.to_string()))?,
            StoredAuthenticationState::Discoverable(mut state) => {
                let Some(passkey) = credential.as_ref() else {
                    return Err(OpenAuthError::Api(
                        "passkey credential is required".to_owned(),
                    ));
                };
                state.set_allowed_credentials(vec![Credential::from(passkey.clone())]);
                core.authenticate_credential(&response, &state)
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?
            }
        };
        let updated_credential = credential.and_then(|mut passkey| {
            passkey
                .update_credential(&result)
                .and_then(|changed| changed.then_some(passkey))
        });
        Ok(VerifiedAuthentication {
            credential: updated_credential
                .map(|passkey| serde_json::to_value(passkey).map_err(json_error))
                .transpose()?,
            new_counter: result.counter(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum StoredAuthenticationState {
    Passkey(AuthenticationState),
    Discoverable(AuthenticationState),
}

/// Builds the low-level WebAuthn verifier.
///
/// `WebauthnCore::new_unsafe_experts_only` is required here because OpenAuth must
/// opt into loopback-only `allow_any_port` origin matching (see `origins_allow_any_port`).
/// The high-level `WebauthnBuilder` path does not expose that control without the same
/// expert constructor. Callers must already have resolved `rp_id` and `origins` via
/// `routes::webauthn_config`, which fails closed instead of defaulting to localhost.
fn core(config: &WebAuthnConfig) -> Result<WebauthnCore, OpenAuthError> {
    if config.origins.is_empty() {
        return Err(OpenAuthError::InvalidConfig(
            "passkey origin is required".to_owned(),
        ));
    }
    let mut origins = Vec::with_capacity(config.origins.len());
    for origin in &config.origins {
        let url = Url::parse(origin).map_err(|error| OpenAuthError::Api(error.to_string()))?;
        // Preserve the `WebauthnBuilder::new` security check: rp_id must be an
        // effective domain of every configured origin.
        let valid = url.domain().is_some_and(|domain| {
            domain == config.rp_id || domain.ends_with(&format!(".{}", config.rp_id))
        });
        if !valid {
            return Err(OpenAuthError::Api(format!(
                "passkey rp_id `{}` is not an effective domain of origin `{origin}`",
                config.rp_id
            )));
        }
        origins.push(url);
    }
    Ok(WebauthnCore::new_unsafe_experts_only(
        &config.rp_name,
        &config.rp_id,
        origins.clone(),
        Duration::from_secs(300),
        Some(false),
        Some(origins_allow_any_port(&origins)),
    ))
}

fn user_verification_policy(value: UserVerificationRequirement) -> UserVerificationPolicy {
    match value {
        UserVerificationRequirement::Discouraged => UserVerificationPolicy::Discouraged_DO_NOT_USE,
        UserVerificationRequirement::Preferred => UserVerificationPolicy::Preferred,
        UserVerificationRequirement::Required => UserVerificationPolicy::Required,
    }
}

/// `WebauthnBuilder::allow_any_port` skips the port check for *every* configured
/// origin, and ports are part of the browser origin boundary. Enabling it
/// unconditionally would let a production origin such as `https://auth.example.com`
/// also accept `https://auth.example.com:8443`, so it is restricted to local
/// development.
///
/// Returns `true` only when every origin is a loopback/localhost host, so a
/// single non-loopback origin forces exact-port matching for the whole set.
fn origins_allow_any_port(origins: &[Url]) -> bool {
    !origins.is_empty() && origins.iter().all(is_loopback_origin)
}

fn is_loopback_origin(origin: &Url) -> bool {
    match origin.host() {
        Some(url::Host::Domain(host)) => host == "localhost" || host.ends_with(".localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn option_value(options: CreationChallengeResponse) -> Result<Value, OpenAuthError> {
    serde_json::to_value(options)
        .map(|mut value| value.pointer_mut("/publicKey").cloned().unwrap_or(value))
        .map_err(json_error)
}

fn auth_option_value(options: RequestChallengeResponse) -> Result<Value, OpenAuthError> {
    serde_json::to_value(options)
        .map(|mut value| value.pointer_mut("/publicKey").cloned().unwrap_or(value))
        .map_err(json_error)
}

fn apply_registration_request_options(
    options: &mut Value,
    request_options: &RegistrationWebAuthnOptions,
) {
    options["authenticatorSelection"] = request_options.authenticator_selection.to_json();
    if let Some(extensions) = &request_options.extensions {
        options["extensions"] = extensions.clone();
    }
}

fn apply_authentication_request_options(options: &mut Value, extensions: Option<Value>) {
    if let Some(extensions) = extensions {
        options["extensions"] = extensions;
    }
}

fn credential_value_to_passkey(value: Value) -> Result<Passkey, OpenAuthError> {
    serde_json::from_value::<Passkey>(value).map_err(json_error)
}

fn parse_exclude_credential_id(value: Value) -> Result<CredentialID, OpenAuthError> {
    if let Ok(credential) = serde_json::from_value::<Credential>(value.clone()) {
        return Ok(credential.cred_id);
    }
    let id = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .ok_or_else(|| OpenAuthError::Api("invalid passkey exclude credential entry".to_owned()))?;
    serde_json::from_value(json!(id)).map_err(json_error)
}

/// Reconstruct `webauthn-rs` credential state from legacy passkey columns.
///
/// Rows created before OpenAuth stored hidden `webauthn_credential` JSON only
/// persisted the base64 COSE public key and passkey metadata. Authentication
/// must rebuild enough state for verification and counter updates.
pub(crate) fn legacy_passkey_credential_value(
    credential_id: &str,
    public_key: &str,
    counter: i64,
    device_type: &str,
    backed_up: bool,
    transports: Option<&str>,
) -> Result<Value, OpenAuthError> {
    let cose_bytes = decode_stored_public_key(public_key)?;
    let cbor = serde_cbor_2::from_slice::<serde_cbor_2::Value>(&cose_bytes)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let cose_key =
        COSEKey::try_from(&cbor).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let cred_id: CredentialID = serde_json::from_value(json!(credential_id)).map_err(json_error)?;
    let transports = transports.map(parse_stored_transports).transpose()?;
    let counter = u32::try_from(counter)
        .map_err(|_| OpenAuthError::Api("passkey counter exceeds u32 range".to_owned()))?;
    let credential = Credential {
        cred_id,
        cred: cose_key,
        counter,
        transports,
        user_verified: false,
        backup_eligible: device_type == "multiDevice",
        backup_state: backed_up,
        registration_policy: UserVerificationPolicy::Preferred,
        extensions: RegisteredExtensions::none(),
        attestation: ParsedAttestation::default(),
        attestation_format: AttestationFormat::None,
    };
    serde_json::to_value(Passkey::from(credential)).map_err(json_error)
}

fn decode_stored_public_key(public_key: &str) -> Result<Vec<u8>, OpenAuthError> {
    use base64::Engine;
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(public_key) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(public_key) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn parse_stored_transports(value: &str) -> Result<Vec<AuthenticatorTransport>, OpenAuthError> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            AuthenticatorTransport::from_str(part)
                .map_err(|_| OpenAuthError::Api(format!("unsupported passkey transport `{part}`")))
        })
        .collect()
}

fn credential_output(passkey: Passkey) -> Result<VerifiedPasskeyCredential, OpenAuthError> {
    let credential = Credential::from(passkey.clone());
    let aaguid = aaguid_from_attestation_metadata(&credential.attestation.metadata);
    let credential_id = serde_json::to_value(&credential.cred_id)
        .and_then(serde_json::from_value::<String>)
        .unwrap_or_else(|_| format!("{:?}", credential.cred_id));
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(cose_public_key_bytes(&credential.cred)?);
    let transports = credential.transports.as_ref().map(|values| {
        values
            .iter()
            .map(|value| {
                serde_json::to_value(value)
                    .ok()
                    .and_then(|value| serde_json::from_value::<String>(value).ok())
                    .unwrap_or_else(|| format!("{value:?}").to_ascii_lowercase())
            })
            .collect::<Vec<_>>()
            .join(",")
    });
    Ok(VerifiedPasskeyCredential {
        credential_id,
        public_key,
        counter: credential.counter,
        device_type: if credential.backup_eligible {
            "multiDevice".to_owned()
        } else {
            "singleDevice".to_owned()
        },
        backed_up: credential.backup_state,
        transports,
        aaguid,
        credential: serde_json::to_value(passkey).map_err(json_error)?,
    })
}

fn aaguid_from_attestation_metadata(metadata: &AttestationMetadata) -> Option<String> {
    match metadata {
        AttestationMetadata::Packed { aaguid } | AttestationMetadata::Tpm { aaguid, .. } => {
            Some(aaguid.to_string())
        }
        _ => None,
    }
}

fn cose_public_key_bytes(key: &COSEKey) -> Result<Vec<u8>, OpenAuthError> {
    let mut values = BTreeMap::new();
    values.insert(
        serde_cbor_2::Value::Integer(1),
        serde_cbor_2::Value::Integer(cose_key_type_id(&key.key)),
    );
    values.insert(
        serde_cbor_2::Value::Integer(3),
        serde_cbor_2::Value::Integer(cose_algorithm_id(key.type_)?),
    );
    match &key.key {
        COSEKeyType::EC_EC2(key) => {
            values.insert(
                serde_cbor_2::Value::Integer(-1),
                serde_cbor_2::Value::Integer(ecdsa_curve_id(&key.curve)),
            );
            values.insert(
                serde_cbor_2::Value::Integer(-2),
                serde_cbor_2::Value::Bytes(key.x.as_ref().to_vec()),
            );
            values.insert(
                serde_cbor_2::Value::Integer(-3),
                serde_cbor_2::Value::Bytes(key.y.as_ref().to_vec()),
            );
        }
        COSEKeyType::RSA(key) => {
            values.insert(
                serde_cbor_2::Value::Integer(-1),
                serde_cbor_2::Value::Bytes(key.n.as_ref().to_vec()),
            );
            values.insert(
                serde_cbor_2::Value::Integer(-2),
                serde_cbor_2::Value::Bytes(key.e.to_vec()),
            );
        }
        COSEKeyType::EC_OKP(key) => {
            values.insert(
                serde_cbor_2::Value::Integer(-1),
                serde_cbor_2::Value::Integer(eddsa_curve_id(&key.curve)),
            );
            values.insert(
                serde_cbor_2::Value::Integer(-2),
                serde_cbor_2::Value::Bytes(key.x.as_ref().to_vec()),
            );
        }
    }
    serde_cbor_2::to_vec(&serde_cbor_2::Value::Map(values))
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn cose_key_type_id(key: &COSEKeyType) -> i128 {
    match key {
        COSEKeyType::EC_OKP(_) => 1,
        COSEKeyType::EC_EC2(_) => 2,
        COSEKeyType::RSA(_) => 3,
    }
}

fn cose_algorithm_id(algorithm: COSEAlgorithm) -> Result<i128, OpenAuthError> {
    match algorithm {
        COSEAlgorithm::ES256 => Ok(-7),
        COSEAlgorithm::ES384 => Ok(-35),
        COSEAlgorithm::ES512 => Ok(-36),
        COSEAlgorithm::RS256 => Ok(-257),
        COSEAlgorithm::RS384 => Ok(-258),
        COSEAlgorithm::RS512 => Ok(-259),
        COSEAlgorithm::PS256 => Ok(-37),
        COSEAlgorithm::PS384 => Ok(-38),
        COSEAlgorithm::PS512 => Ok(-39),
        COSEAlgorithm::EDDSA => Ok(-8),
        COSEAlgorithm::INSECURE_RS1 => Ok(-65535),
        COSEAlgorithm::PinUvProtocol => Err(OpenAuthError::Api(
            "passkey public key uses an unsupported COSE algorithm".to_owned(),
        )),
    }
}

fn ecdsa_curve_id(curve: &ECDSACurve) -> i128 {
    match curve {
        ECDSACurve::SECP256R1 => 1,
        ECDSACurve::SECP384R1 => 2,
        ECDSACurve::SECP521R1 => 3,
    }
}

fn eddsa_curve_id(curve: &EDDSACurve) -> i128 {
    match curve {
        EDDSACurve::ED25519 => 6,
        EDDSACurve::ED448 => 7,
    }
}

fn json_error(error: serde_json::Error) -> OpenAuthError {
    OpenAuthError::Api(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor_2::Value as CborValue;
    use webauthn_rs::prelude::{AttestationMetadata, Credential};

    fn parse_origins(origins: &[&str]) -> Result<Vec<Url>, url::ParseError> {
        origins.iter().map(|origin| Url::parse(origin)).collect()
    }

    #[test]
    fn production_origins_keep_exact_port_matching() -> Result<(), url::ParseError> {
        // A configured https://example.com must not be treated as valid for
        // https://example.com:8443, so any-port matching stays disabled.
        assert!(!origins_allow_any_port(&parse_origins(&[
            "https://example.com"
        ])?));
        assert!(!origins_allow_any_port(&parse_origins(&[
            "https://auth.example.com:443"
        ])?));
        Ok(())
    }

    #[test]
    fn loopback_origins_allow_any_port_for_local_dev() -> Result<(), url::ParseError> {
        // Local development servers run on arbitrary ports, so loopback hosts
        // keep any-port matching.
        for origin in [
            "http://localhost",
            "http://localhost:3000",
            "http://app.localhost:9000",
            "http://127.0.0.1:5173",
            "http://[::1]:8080",
        ] {
            assert!(
                origins_allow_any_port(&parse_origins(&[origin])?),
                "{origin} should allow any port"
            );
        }
        Ok(())
    }

    #[test]
    fn mixed_origins_preserve_exact_port_checks() -> Result<(), url::ParseError> {
        // A single non-loopback origin forces exact-port matching for the
        // whole set, since allow_any_port is global to the verifier.
        assert!(!origins_allow_any_port(&parse_origins(&[
            "http://localhost:3000",
            "https://example.com",
        ])?));
        assert!(origins_allow_any_port(&parse_origins(&[
            "http://localhost:3000",
            "http://127.0.0.1:5173",
        ])?));
        Ok(())
    }

    #[test]
    fn webauthn_builds_for_production_and_loopback_configs() -> Result<(), OpenAuthError> {
        let production = WebAuthnConfig {
            rp_id: "example.com".to_owned(),
            rp_name: "Example".to_owned(),
            origins: vec!["https://auth.example.com".to_owned()],
        };
        let loopback = WebAuthnConfig {
            rp_id: "localhost".to_owned(),
            rp_name: "Example".to_owned(),
            origins: vec!["http://localhost:3000".to_owned()],
        };
        core(&production)?;
        core(&loopback)?;
        Ok(())
    }

    #[test]
    fn aaguid_from_attestation_metadata_extracts_packed_and_tpm_values() {
        let packed = Uuid::from_u128(1);
        let tpm = Uuid::from_u128(2);

        assert_eq!(
            aaguid_from_attestation_metadata(&AttestationMetadata::Packed { aaguid: packed }),
            Some(packed.to_string())
        );
        assert_eq!(
            aaguid_from_attestation_metadata(&AttestationMetadata::Tpm {
                aaguid: tpm,
                firmware_version: 1,
            }),
            Some(tpm.to_string())
        );
        assert_eq!(
            aaguid_from_attestation_metadata(&AttestationMetadata::None),
            None
        );
    }

    #[test]
    fn credential_output_public_key_is_cose_cbor_base64() -> Result<(), Box<dyn std::error::Error>>
    {
        let credential = serde_json::from_value::<Credential>(serde_json::json!({
            "cred_id": "AQID",
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                        "y": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
                    }
                }
            },
            "counter": 7,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "preferred",
            "extensions": {
                "cred_protect": "NotRequested",
                "hmac_create_secret": "NotRequested"
            },
            "attestation": {
                "data": "None",
                "metadata": "None"
            },
            "attestation_format": "none"
        }))?;
        let output = credential_output(credential.into())?;
        let public_key_bytes =
            base64::engine::general_purpose::STANDARD.decode(output.public_key)?;
        let public_key = serde_cbor_2::from_slice::<CborValue>(&public_key_bytes)?;
        let CborValue::Map(values) = public_key else {
            return Err("COSE public key must be encoded as a CBOR map".into());
        };

        assert_eq!(
            values.get(&CborValue::Integer(1)),
            Some(&CborValue::Integer(2))
        );
        assert_eq!(
            values.get(&CborValue::Integer(3)),
            Some(&CborValue::Integer(-7))
        );
        assert_eq!(
            values.get(&CborValue::Integer(-1)),
            Some(&CborValue::Integer(1))
        );
        assert_eq!(
            values.get(&CborValue::Integer(-2)),
            Some(&CborValue::Bytes(vec![1; 32]))
        );
        assert_eq!(
            values.get(&CborValue::Integer(-3)),
            Some(&CborValue::Bytes(vec![2; 32]))
        );
        Ok(())
    }

    fn sample_test_credential() -> Result<Credential, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(serde_json::json!({
            "cred_id": "AQID",
            "cred": {
                "type_": "ES256",
                "key": { "EC_EC2": {
                    "curve": "SECP256R1",
                    "x": [
                        101, 237, 165, 161, 37, 119, 194, 186, 232, 41, 67, 127, 227, 56, 112, 26,
                        16, 170, 163, 117, 225, 187, 91, 93, 225, 8, 222, 67, 156, 8, 85, 29
                    ],
                    "y": [
                        30, 82, 237, 117, 112, 17, 99, 247, 249, 228, 13, 223, 159, 52, 27, 61,
                        201, 186, 134, 10, 247, 224, 202, 124, 167, 233, 238, 205, 0, 132, 209, 156
                    ]
                } }
            },
            "counter": 0,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "preferred",
            "extensions": { "cred_protect": "NotRequested", "hmac_create_secret": "NotRequested" },
            "attestation": { "data": "None", "metadata": "None" },
            "attestation_format": "none"
        }))?)
    }

    #[test]
    fn legacy_passkey_credential_value_reconstructs_from_stored_public_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = credential_output(sample_test_credential()?.into())?;
        let reconstructed = legacy_passkey_credential_value(
            &output.credential_id,
            &output.public_key,
            i64::from(output.counter),
            &output.device_type,
            output.backed_up,
            output.transports.as_deref(),
        )?;
        credential_value_to_passkey(reconstructed)?;
        Ok(())
    }

    #[test]
    fn legacy_passkey_credential_value_rejects_invalid_public_key() {
        let result = legacy_passkey_credential_value(
            "AQID",
            "not-valid-cose",
            0,
            "singleDevice",
            false,
            None,
        );
        assert!(result.is_err());
    }
}
