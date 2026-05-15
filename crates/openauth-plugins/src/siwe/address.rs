use std::error::Error;
use std::fmt;

use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiweAddressError {
    InvalidFormat,
}

impl fmt::Display for SiweAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => formatter.write_str("invalid Ethereum address format"),
        }
    }
}

impl Error for SiweAddressError {}

pub fn checksum_address(address: &str) -> Result<String, SiweAddressError> {
    if !is_valid_address(address) {
        return Err(SiweAddressError::InvalidFormat);
    }
    let lower = address[2..].to_ascii_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (index, byte) in lower.bytes().enumerate() {
        let hash_byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if byte.is_ascii_alphabetic() && nibble >= 8 {
            result.push((byte as char).to_ascii_uppercase());
        } else {
            result.push(byte as char);
        }
    }
    Ok(result)
}

fn is_valid_address(address: &str) -> bool {
    address.len() == 42
        && address
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"))
        && address[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
