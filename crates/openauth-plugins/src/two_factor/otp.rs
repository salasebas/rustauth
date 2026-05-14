use data_encoding::BASE64URL_NOPAD;
use openauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use openauth_core::error::OpenAuthError;
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

pub fn store_otp(otp: &str, secret: &str, options: &OtpOptions) -> Result<String, OpenAuthError> {
    match options.storage {
        OtpStorage::Plain => Ok(otp.to_owned()),
        OtpStorage::Encrypted => symmetric_encrypt(secret, otp),
        OtpStorage::Hashed => Ok(hash_otp(otp)),
    }
}

pub fn verify_stored_otp(
    stored: &str,
    input: &str,
    secret: &str,
    options: &OtpOptions,
) -> Result<bool, OpenAuthError> {
    let expected = match options.storage {
        OtpStorage::Plain => stored.to_owned(),
        OtpStorage::Encrypted => symmetric_decrypt(secret, stored)?,
        OtpStorage::Hashed => stored.to_owned(),
    };
    Ok(expected
        .as_bytes()
        .ct_eq(input_for_compare(input, options).as_bytes())
        .into())
}

fn input_for_compare(input: &str, options: &OtpOptions) -> String {
    match options.storage {
        OtpStorage::Hashed => hash_otp(input),
        OtpStorage::Plain | OtpStorage::Encrypted => input.to_owned(),
    }
}

fn hash_otp(otp: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(otp.as_bytes()))
}
