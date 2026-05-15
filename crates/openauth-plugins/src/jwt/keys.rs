use openauth_core::error::OpenAuthError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwkAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES512")]
    Es512,
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "PS256")]
    Ps256,
}

impl JwkAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es512 => "ES512",
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub created_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub alg: Option<JwkAlgorithm>,
    pub crv: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Value>,
}

pub(crate) fn generate_jwk(options: &super::JwtOptions) -> Result<Jwk, OpenAuthError> {
    let algorithm = options.algorithm();
    let mut private = match algorithm {
        JwkAlgorithm::EdDsa => {
            use josekit::jwk::alg::ed::EdCurve::Ed25519;
            josekit::jwk::Jwk::generate_ed_key(Ed25519)
        }
        JwkAlgorithm::Es256 => {
            use josekit::jwk::alg::ec::EcCurve::P256;
            josekit::jwk::Jwk::generate_ec_key(P256)
        }
        JwkAlgorithm::Es512 => {
            use josekit::jwk::alg::ec::EcCurve::P521;
            josekit::jwk::Jwk::generate_ec_key(P521)
        }
        JwkAlgorithm::Rs256 | JwkAlgorithm::Ps256 => {
            josekit::jwk::Jwk::generate_rsa_key(options.jwks.rsa_modulus_length.unwrap_or(2048))
        }
    }
    .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    private.set_algorithm(algorithm.as_str());
    private.set_key_use("sig");
    private.set_key_operations(vec!["sign"]);

    let id = random_id();
    private.set_key_id(&id);
    let mut public = private
        .to_public_key()
        .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    public.set_algorithm(algorithm.as_str());
    public.set_key_use("sig");
    public.set_key_operations(vec!["verify"]);
    public.set_key_id(&id);

    let now = OffsetDateTime::now_utc();
    let expires_at = options
        .jwks
        .rotation_interval
        .map(|seconds| now + time::Duration::seconds(seconds));

    Ok(Jwk {
        id,
        public_key: serde_json::to_string(&public)
            .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        private_key: serde_json::to_string(&private)
            .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        created_at: now,
        expires_at,
        alg: Some(algorithm),
        crv: public.curve().map(str::to_owned),
    })
}

pub(crate) fn public_jwk_value(
    key: &Jwk,
    options: &super::JwtOptions,
) -> Result<Value, OpenAuthError> {
    let mut value: Value = serde_json::from_str(&key.public_key)
        .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    let Value::Object(map) = &mut value else {
        return Err(OpenAuthError::Crypto(
            "public JWK must be an object".to_owned(),
        ));
    };
    map.insert("kid".to_owned(), Value::String(key.id.clone()));
    map.insert(
        "alg".to_owned(),
        Value::String(
            key.alg
                .unwrap_or_else(|| options.algorithm())
                .as_str()
                .to_owned(),
        ),
    );
    if let Some(crv) = &key.crv {
        map.entry("crv".to_owned())
            .or_insert_with(|| Value::String(crv.clone()));
    }
    map.remove("d");
    Ok(value)
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    )
}
