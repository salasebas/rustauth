use openauth_core::api::AuthRouter;
use openauth_core::context::create_auth_context;
use openauth_core::options::OpenAuthOptions;
use openauth_passkey::{passkey, PasskeyOptions};

#[test]
fn passkey_endpoints_expose_openapi_and_body_schemas() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![passkey(PasskeyOptions::default())],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::try_new(context, Vec::new())?;
    let schema = router.openapi_schema();

    let verify_registration = &schema["paths"]["/passkey/verify-registration"]["post"];
    assert_eq!(
        verify_registration["operationId"],
        "passkeyVerifyRegistration"
    );
    assert_eq!(verify_registration["tags"][0], "Passkey");
    assert_eq!(
        verify_registration["requestBody"]["content"]["application/json"]["schema"]["required"][0],
        "response"
    );
    assert_eq!(
        verify_registration["responses"]["200"]["content"]["application/json"]["schema"]
            ["properties"]["credentialID"]["type"],
        "string"
    );

    let update = &schema["paths"]["/passkey/update-passkey"]["post"];
    assert_eq!(
        update["requestBody"]["content"]["application/json"]["schema"]["required"][0],
        "id"
    );
    assert_eq!(
        update["requestBody"]["content"]["application/json"]["schema"]["required"][1],
        "name"
    );

    let generate = &schema["paths"]["/passkey/generate-register-options"]["get"];
    assert_eq!(
        generate["operationId"],
        "generatePasskeyRegistrationOptions"
    );
    assert!(generate["parameters"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["name"] == "context")));

    Ok(())
}
