use rustauth_sso::SsoOptions;

use super::support::router_with_options;

#[test]
fn sso_openapi_exposes_public_route_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let options = SsoOptions::default().domain_verification_enabled(true);
    #[cfg(feature = "saml")]
    let options = {
        let mut options = options;
        options.saml.enable_single_logout = true;
        options
    };
    let (_, router) = router_with_options(options)?;
    let openapi = router.openapi_schema();

    assert_eq!(
        openapi["paths"]["/sign-in/sso"]["post"]["operationId"],
        "signInWithSSO"
    );
    assert!(
        openapi["paths"]["/sign-in/sso"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"]["providerId"]
            .is_object()
    );
    assert!(
        openapi["paths"]["/sso/register"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"]["oidcConfig"]
            .is_object()
    );
    assert!(
        openapi["paths"]["/sso/register"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"]["oidcConfig"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("skipDiscovery"))
    );
    assert_eq!(
        openapi["paths"]["/sso/register"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["oidcConfig"]["properties"]
            ["revocationEndpoint"]["format"],
        "uri"
    );
    assert_eq!(
        openapi["paths"]["/sso/register"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["oidcConfig"]["properties"]
            ["tokenEndpointAuthentication"]["enum"][0],
        "client_secret_basic"
    );
    assert_eq!(
        openapi["paths"]["/sso/providers"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["providers"]["items"]["properties"]
            ["providerId"]["type"],
        "string"
    );
    assert_eq!(
        openapi["paths"]["/sso/get-provider"]["get"]["parameters"][0]["in"],
        "query"
    );
    assert_eq!(
        openapi["paths"]["/sso/get-provider"]["get"]["parameters"][0]["name"],
        "providerId"
    );
    assert_eq!(
        openapi["paths"]["/sso/get-provider"]["get"]["responses"]["400"]["content"]
            ["application/json"]["schema"]["properties"]["code"]["type"],
        "string"
    );
    assert_eq!(
        openapi["paths"]["/sso/delete-provider"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["success"]["type"],
        "boolean"
    );
    assert_eq!(
        openapi["paths"]["/sign-in/sso"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["url"]["format"],
        "uri"
    );
    assert!(
        openapi["paths"]["/sso/update-provider"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["samlConfig"]
            .is_object()
    );
    #[cfg(feature = "saml")]
    {
        assert_eq!(
            openapi["paths"]["/sso/saml2/logout/{providerId}"]["post"]["parameters"][0]["name"],
            "providerId"
        );
        assert!(
            openapi["paths"]["/sso/saml2/logout/{providerId}"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["properties"]["callbackURL"]
                .is_object()
        );
        assert!(
            openapi["paths"]["/sso/saml2/sp/slo/{providerId}"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["properties"]["SAMLRequest"]
                .is_object()
        );
    }
    assert_eq!(
        openapi["paths"]["/sso/request-domain-verification"]["post"]["operationId"],
        "requestDomainVerification"
    );
    assert_eq!(
        openapi["paths"]["/sso/request-domain-verification"]["post"]["responses"]["201"]["content"]
            ["application/json"]["schema"]["properties"]["domainVerificationToken"]["type"],
        "string"
    );
    assert_eq!(
        openapi["paths"]["/sso/verify-domain"]["post"]["operationId"],
        "verifyDomain"
    );
    assert_eq!(
        openapi["paths"]["/sso/verify-domain"]["post"]["responses"]["502"]["content"]
            ["application/json"]["schema"]["properties"]["code"]["type"],
        "string"
    );
    #[cfg(feature = "oidc")]
    {
        assert_eq!(
            openapi["paths"]["/sso/callback/{providerId}"]["get"]["operationId"],
            "handleSSOCallback"
        );
        assert_eq!(
            openapi["paths"]["/sso/callback"]["get"]["operationId"],
            "handleSSOCallbackShared"
        );
    }

    Ok(())
}

#[test]
fn sso_openapi_hides_idp_post_callback_routes() -> Result<(), Box<dyn std::error::Error>> {
    let (_, router) = router_with_options(SsoOptions::default())?;
    let openapi = router.openapi_schema();

    assert!(openapi["paths"]["/sso/saml2/callback/{providerId}"].is_null());
    assert!(openapi["paths"]["/sso/saml2/sp/acs/{providerId}"].is_null());

    Ok(())
}
