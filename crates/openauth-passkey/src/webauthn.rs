use base64::Engine;
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationMetadata, COSEAlgorithm, COSEKey, COSEKeyType, CreationChallengeResponse,
    Credential, DiscoverableAuthentication, DiscoverableKey, ECDSACurve, EDDSACurve,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::options::{PasskeyRegistrationUser, RegistrationWebAuthnOptions};

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
        let webauthn = webauthn(&config)?;
        let exclude = exclude_credentials
            .into_iter()
            .map(|value| {
                serde_json::from_value::<Credential>(value).map(|credential| credential.cred_id)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let user_id = Uuid::new_v4();
        let display_name = user.display_name.as_deref().unwrap_or(&user.name);
        let (options, state) = webauthn
            .start_passkey_registration(user_id, &user.name, display_name, Some(exclude))
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
        let webauthn = webauthn(&config)?;
        let response = serde_json::from_value::<RegisterPublicKeyCredential>(response)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let state = serde_json::from_value::<PasskeyRegistration>(state).map_err(json_error)?;
        let passkey = webauthn
            .finish_passkey_registration(&response, &state)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        credential_output(passkey)
    }

    fn start_authentication(
        &self,
        config: WebAuthnConfig,
        credentials: Vec<Value>,
        extensions: Option<Value>,
    ) -> Result<PasskeyAuthenticationStart, OpenAuthError> {
        let webauthn = webauthn(&config)?;
        if credentials.is_empty() {
            let (options, state) = webauthn
                .start_discoverable_authentication()
                .map_err(|error| OpenAuthError::Api(error.to_string()))?;
            let mut options = auth_option_value(options)?;
            apply_authentication_request_options(&mut options, extensions);
            return Ok(PasskeyAuthenticationStart {
                options,
                state: serde_json::to_value(StoredAuthenticationState::Discoverable(state))
                    .map_err(json_error)?,
            });
        }
        let passkeys = credentials
            .into_iter()
            .map(credential_value_to_passkey)
            .collect::<Result<Vec<_>, _>>()?;
        let (options, state) = webauthn
            .start_passkey_authentication(&passkeys)
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
        let webauthn = webauthn(&config)?;
        let response = serde_json::from_value::<PublicKeyCredential>(response)
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        let state =
            serde_json::from_value::<StoredAuthenticationState>(state).map_err(json_error)?;
        let credential = credential.map(credential_value_to_passkey).transpose()?;
        let result = match state {
            StoredAuthenticationState::Passkey(state) => webauthn
                .finish_passkey_authentication(&response, &state)
                .map_err(|error| OpenAuthError::Api(error.to_string()))?,
            StoredAuthenticationState::Discoverable(state) => {
                let Some(credential) = credential.as_ref() else {
                    return Err(OpenAuthError::Api(
                        "passkey credential is required".to_owned(),
                    ));
                };
                let discoverable = DiscoverableKey::from(credential);
                webauthn
                    .finish_discoverable_authentication(&response, state, &[discoverable])
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
    Passkey(PasskeyAuthentication),
    Discoverable(DiscoverableAuthentication),
}

fn webauthn(config: &WebAuthnConfig) -> Result<Webauthn, OpenAuthError> {
    let primary_origin = config
        .origins
        .first()
        .ok_or_else(|| OpenAuthError::InvalidConfig("passkey origin is required".to_owned()))?;
    let primary =
        Url::parse(primary_origin).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut builder = WebauthnBuilder::new(&config.rp_id, &primary)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?
        .rp_name(&config.rp_name)
        .allow_any_port(true);
    for origin in config.origins.iter().skip(1) {
        let origin = Url::parse(origin).map_err(|error| OpenAuthError::Api(error.to_string()))?;
        builder = builder.append_allowed_origin(&origin);
    }
    builder
        .build()
        .map_err(|error| OpenAuthError::Api(error.to_string()))
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
    options["userVerification"] = Value::String("preferred".to_owned());
    if let Some(extensions) = extensions {
        options["extensions"] = extensions;
    }
}

fn credential_value_to_passkey(
    value: Value,
) -> Result<webauthn_rs::prelude::Passkey, OpenAuthError> {
    serde_json::from_value::<webauthn_rs::prelude::Passkey>(value).map_err(json_error)
}

fn credential_output(
    passkey: webauthn_rs::prelude::Passkey,
) -> Result<VerifiedPasskeyCredential, OpenAuthError> {
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
}
