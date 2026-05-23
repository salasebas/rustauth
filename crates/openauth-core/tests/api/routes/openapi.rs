use super::*;

#[test]
fn core_auth_routes_expose_upstream_openapi_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter)?;
    let openapi = router.openapi_schema();

    assert_eq!(
        openapi["paths"]["/sign-up/email"]["post"]["responses"]["200"]["description"],
        "Successfully created user"
    );
    assert_eq!(
        openapi["paths"]["/sign-in/email"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["required"],
        serde_json::json!(["redirect", "token", "user"])
    );
    assert_eq!(
        openapi["paths"]["/get-session"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["type"],
        serde_json::json!(["object", "null"])
    );
    assert_eq!(
        openapi["paths"]["/get-session"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["user"]["$ref"],
        "#/components/schemas/User"
    );
    assert_eq!(
        openapi["components"]["schemas"]["User"]["additionalProperties"],
        true
    );
    assert_eq!(
        openapi["components"]["schemas"]["Session"]["additionalProperties"],
        true
    );
    assert_eq!(
        openapi["paths"]["/get-session"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"],
        serde_json::json!({
            "type": "object",
            "properties": {}
        })
    );
    assert_eq!(
        openapi["paths"]["/sign-out"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["success"]["type"],
        "boolean"
    );
    assert_eq!(
        openapi["paths"]["/list-sessions"]["get"]["operationId"],
        "listUserSessions"
    );
    assert_eq!(
        openapi["paths"]["/revoke-session"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["required"],
        serde_json::json!(["token"])
    );
    assert_eq!(
        openapi["paths"]["/change-password"]["post"]["operationId"],
        "changePassword"
    );
    assert_eq!(
        openapi["paths"]["/request-password-reset"]["post"]["operationId"],
        "requestPasswordReset"
    );
    assert_eq!(
        openapi["paths"]["/list-accounts"]["get"]["operationId"],
        "listUserAccounts"
    );
    assert_eq!(
        openapi["paths"]["/unlink-account"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["required"],
        serde_json::json!(["providerId"])
    );
    assert_eq!(
        openapi["paths"]["/send-verification-email"]["post"]["operationId"],
        "sendVerificationEmail"
    );
    assert_eq!(
        openapi["paths"]["/verify-email"]["get"]["operationId"],
        "verifyEmail"
    );
    assert_eq!(
        openapi["paths"]["/change-email"]["post"]["operationId"],
        "changeEmail"
    );
    assert_eq!(
        openapi["paths"]["/delete-user"]["post"]["operationId"],
        "deleteUser"
    );
    assert_eq!(
        openapi["paths"]["/delete-user/callback"]["get"]["operationId"],
        "deleteUserCallback"
    );
    Ok(())
}
