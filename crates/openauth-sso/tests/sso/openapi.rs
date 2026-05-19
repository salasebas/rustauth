use openauth_sso::SsoOptions;

use super::support::router_with_options;

#[test]
fn sso_openapi_exposes_public_route_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default().domain_verification_enabled(true);
    options.saml.enable_single_logout = true;
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
        openapi["paths"]["/sso/update-provider"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["samlConfig"]
            .is_object()
    );
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
    assert_eq!(
        openapi["paths"]["/sso/request-domain-verification"]["post"]["operationId"],
        "requestDomainVerification"
    );
    assert_eq!(
        openapi["paths"]["/sso/verify-domain"]["post"]["operationId"],
        "verifyDomain"
    );
    assert_eq!(
        openapi["paths"]["/sso/callback/{providerId}"]["get"]["operationId"],
        "handleSSOCallback"
    );

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
