use openauth_plugins::siwe::{checksum_address, SiweAddressError};

use super::WALLET;

#[test]
fn checksum_address_normalizes_lowercase_input() -> Result<(), SiweAddressError> {
    assert_eq!(checksum_address(&WALLET.to_lowercase())?, WALLET);
    Ok(())
}

#[test]
fn checksum_address_rejects_non_ethereum_address() {
    assert!(matches!(
        checksum_address("not_a_wallet"),
        Err(SiweAddressError::InvalidFormat)
    ));
}
