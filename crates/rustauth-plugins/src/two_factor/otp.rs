use data_encoding::BASE64URL_NOPAD;
use rustauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use rustauth_core::error::RustAuthError;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::options::{OtpOptions, OtpStorage};

pub fn generate_otp(digits: usize) -> String {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    (0..digits)
        .map(|_| char::from(b'0' + rng.gen_range(0..10)))
        .collect()
}

pub async fn store_otp(
    otp: &str,
    secret: &str,
    options: &OtpOptions,
) -> Result<String, RustAuthError> {
    match &options.storage {
        OtpStorage::Plain => Ok(otp.to_owned()),
        OtpStorage::Encrypted => symmetric_encrypt(secret, otp),
        OtpStorage::Hashed => Ok(hash_otp(otp)),
        OtpStorage::CustomHash(hash) => (hash)(otp.to_owned()).await,
        OtpStorage::CustomEncrypt { encrypt, .. } => (encrypt)(otp.to_owned()).await,
    }
}

pub async fn verify_stored_otp(
    stored: &str,
    input: &str,
    secret: &str,
    options: &OtpOptions,
) -> Result<bool, RustAuthError> {
    match &options.storage {
        OtpStorage::Plain => Ok(stored.as_bytes().ct_eq(input.as_bytes()).into()),
        OtpStorage::Encrypted => {
            let expected = symmetric_decrypt(secret, stored)?;
            Ok(expected.as_bytes().ct_eq(input.as_bytes()).into())
        }
        OtpStorage::Hashed => Ok(stored.as_bytes().ct_eq(hash_otp(input).as_bytes()).into()),
        OtpStorage::CustomHash(hash) => {
            let hashed_input = (hash)(input.to_owned()).await?;
            Ok(stored.as_bytes().ct_eq(hashed_input.as_bytes()).into())
        }
        OtpStorage::CustomEncrypt { decrypt, .. } => {
            let expected = (decrypt)(stored.to_owned()).await?;
            Ok(expected.as_bytes().ct_eq(input.as_bytes()).into())
        }
    }
}

fn hash_otp(otp: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(otp.as_bytes()))
}
