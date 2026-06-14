use rustauth_scim::token::{decode_bearer_token, encode_bearer_token, hash_base_token};

#[test]
fn token_round_trips_provider_and_org_with_colons() {
    let token = encode_bearer_token("base-token", "provider", Some("org:with:colon"));
    let decoded = decode_bearer_token(&token).expect("token should decode");

    assert_eq!(decoded.base_token, "base-token");
    assert_eq!(decoded.provider_id, "provider");
    assert_eq!(decoded.organization_id.as_deref(), Some("org:with:colon"));
}

#[test]
fn token_decoder_accepts_padded_upstream_default_provider_token() {
    let decoded = decode_bearer_token("dGhlLXNjaW0tdG9rZW46dGhlLXNjaW0tcHJvdmlkZXI=")
        .expect("padded token should decode");

    assert_eq!(decoded.base_token, "the-scim-token");
    assert_eq!(decoded.provider_id, "the-scim-provider");
    assert_eq!(decoded.organization_id, None);
}

#[test]
fn hash_base_token_matches_stable_sha256_base64url() {
    assert_eq!(
        hash_base_token("the-scim-token"),
        "cTb0JdCvfrVV7V6gJp7-JsJmHRKARPde256FQTk1WiI"
    );
}
