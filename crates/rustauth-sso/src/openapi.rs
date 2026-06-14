use rustauth_core::api::{BodyField, BodySchema, JsonSchemaType};
use serde_json::{json, Value};

pub fn provider_id_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("providerId", JsonSchemaType::String)])
}

pub fn provider_id_query_parameter() -> Value {
    json!({
        "name": "providerId",
        "in": "query",
        "required": true,
        "schema": {"type": "string", "minLength": 1, "maxLength": 128},
    })
}

pub fn register_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String),
        BodyField::new("issuer", JsonSchemaType::String).format("uri"),
        BodyField::new("domain", JsonSchemaType::String),
        BodyField::optional("organizationId", JsonSchemaType::String),
        BodyField::optional("oidcConfig", JsonSchemaType::Object).description(
            "OIDC provider configuration. Manual skipDiscovery endpoints may be validated against trusted origins when strict_oidc_manual_endpoint_origins is enabled.",
        ),
        BodyField::optional("samlConfig", JsonSchemaType::Object),
    ])
}

pub fn update_provider_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("providerId", JsonSchemaType::String),
        BodyField::optional("issuer", JsonSchemaType::String).format("uri"),
        BodyField::optional("domain", JsonSchemaType::String),
        BodyField::optional("organizationId", JsonSchemaType::String),
        BodyField::optional("oidcConfig", JsonSchemaType::Object).description(
            "OIDC provider configuration. Manual skipDiscovery endpoints may be validated against trusted origins when strict_oidc_manual_endpoint_origins is enabled.",
        ),
        BodyField::optional("samlConfig", JsonSchemaType::Object),
    ])
}

pub fn sign_in_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("email", JsonSchemaType::String).format("email"),
        BodyField::optional("domain", JsonSchemaType::String),
        BodyField::optional("providerId", JsonSchemaType::String),
        BodyField::optional("organizationSlug", JsonSchemaType::String),
        BodyField::optional("callbackURL", JsonSchemaType::String).format("uri"),
        BodyField::optional("errorCallbackURL", JsonSchemaType::String).format("uri"),
        BodyField::optional("newUserCallbackURL", JsonSchemaType::String).format("uri"),
        BodyField::optional("loginHint", JsonSchemaType::String),
        BodyField::optional("scopes", JsonSchemaType::Array),
        BodyField::optional("providerType", JsonSchemaType::String),
        BodyField::optional("requestSignUp", JsonSchemaType::Boolean),
    ])
}

#[cfg(feature = "saml")]
pub fn saml_acs_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("SAMLResponse", JsonSchemaType::String),
        BodyField::optional("RelayState", JsonSchemaType::String),
    ])
}

#[cfg(feature = "saml")]
pub fn saml_slo_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("SAMLRequest", JsonSchemaType::String),
        BodyField::optional("SAMLResponse", JsonSchemaType::String),
        BodyField::optional("RelayState", JsonSchemaType::String),
    ])
}

#[cfg(feature = "saml")]
pub fn saml_logout_body_schema() -> BodySchema {
    BodySchema::object([BodyField::optional("callbackURL", JsonSchemaType::String).format("uri")])
}

pub fn sso_provider_response(description: &str) -> Value {
    rustauth_core::api::json_openapi_response(description, sso_provider_schema())
}

pub fn sso_provider_list_response() -> Value {
    rustauth_core::api::json_openapi_response(
        "Accessible SSO providers",
        json!({
            "type": "object",
            "required": ["providers"],
            "properties": {
                "providers": {
                    "type": "array",
                    "items": sso_provider_schema(),
                },
            },
        }),
    )
}

pub fn sign_in_sso_response() -> Value {
    rustauth_core::api::json_openapi_response(
        "SSO authorization redirect URL",
        json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "redirect": {"type": "boolean"},
            },
        }),
    )
}

pub fn domain_verification_token_response(description: &str) -> Value {
    rustauth_core::api::json_openapi_response(
        description,
        json!({
            "type": "object",
            "required": ["domainVerificationToken"],
            "properties": {
                "domainVerificationToken": {"type": "string"},
            },
        }),
    )
}

pub fn success_response(description: &str) -> Value {
    rustauth_core::api::json_openapi_response(
        description,
        json!({
            "type": "object",
            "required": ["success"],
            "properties": {
                "success": {"type": "boolean"},
            },
        }),
    )
}

pub fn error_code_response(description: &str) -> Value {
    rustauth_core::api::json_openapi_response(
        description,
        json!({
            "type": "object",
            "required": ["code"],
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
            },
        }),
    )
}

pub fn redirect_response(description: &str) -> Value {
    rustauth_core::api::redirect_openapi_response(description)
}

#[cfg(feature = "saml")]
pub fn html_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "text/html": {
                "schema": {"type": "string"},
            },
        },
    })
}

#[cfg(feature = "saml")]
pub fn saml_metadata_response() -> Value {
    json!({
        "description": "SAML service provider metadata XML",
        "content": {
            "application/xml": {
                "schema": {"type": "string"},
            },
        },
    })
}

fn sso_provider_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "providerId", "issuer", "domain", "providerType", "type"],
        "properties": {
            "id": {"type": "string"},
            "providerId": {"type": "string"},
            "issuer": {"type": "string"},
            "domain": {"type": "string"},
            "providerType": {"type": "string", "enum": ["oidc", "saml"]},
            "type": {"type": "string", "enum": ["oidc", "saml"]},
            "organizationId": {"type": "string", "nullable": true},
            "domainVerified": {"type": "boolean"},
            "redirectURI": {"type": "string", "format": "uri"},
            "spMetadataUrl": {"type": "string", "format": "uri"},
            "oidcConfig": {
                "type": "object",
                "nullable": true,
                "properties": {
                    "discoveryEndpoint": {"type": "string", "format": "uri"},
                    "clientIdLastFour": {"type": "string"},
                    "pkce": {"type": "boolean"},
                    "authorizationEndpoint": {"type": "string", "format": "uri"},
                    "tokenEndpoint": {"type": "string", "format": "uri"},
                    "userInfoEndpoint": {"type": "string", "format": "uri"},
                    "jwksEndpoint": {"type": "string", "format": "uri"},
                    "revocationEndpoint": {"type": "string", "format": "uri"},
                    "endSessionEndpoint": {"type": "string", "format": "uri"},
                    "introspectionEndpoint": {"type": "string", "format": "uri"},
                    "tokenEndpointAuthentication": {
                        "type": "string",
                        "enum": ["client_secret_basic", "client_secret_post"]
                    },
                    "scopes": {"type": "array", "items": {"type": "string"}},
                },
            },
            "samlConfig": {
                "type": "object",
                "nullable": true,
                "properties": {
                    "entryPoint": {"type": "string", "format": "uri"},
                    "callbackUrl": {"type": "string"},
                    "acsUrl": {"type": "string", "format": "uri"},
                    "audience": {"type": "string"},
                    "wantAssertionsSigned": {"type": "boolean"},
                    "authnRequestsSigned": {"type": "boolean"},
                    "identifierFormat": {"type": "string"},
                    "signatureAlgorithm": {"type": "string"},
                    "digestAlgorithm": {"type": "string"},
                    "certificateSha256Fingerprint": {"type": "string"},
                    "certificateNotBefore": {"type": "string"},
                    "certificateNotAfter": {"type": "string"},
                    "certificatePublicKeyAlgorithm": {"type": "string"},
                    "certificateError": {"type": "string"},
                },
            },
        },
    })
}
