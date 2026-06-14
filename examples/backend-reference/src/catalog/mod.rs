//! Group the public HTTP surface by domain so integrators can navigate endpoints
//! without reading the entire OpenAPI document.

use rustauth::api::EndpointInfo;
use serde::Serialize;

/// Logical grouping for a set of related auth endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointGroup {
    pub id: String,
    pub label: String,
    pub description: String,
    pub endpoints: Vec<EndpointView>,
}

/// Serializable endpoint row for JSON introspection routes.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointView {
    pub method: String,
    pub path: String,
    pub kind: String,
    pub operation_id: String,
    pub media_types: Vec<String>,
}

/// Partition the registry into stable buckets.
pub fn group_endpoints(registry: &[EndpointInfo]) -> Vec<EndpointGroup> {
    let mut groups = vec![
        group(
            "core",
            "Core auth",
            "Sign-in, sign-up, sessions, accounts, passwords",
            registry,
            |path| {
                path.starts_with("/sign-")
                    || path.starts_with("/session")
                    || path.starts_with("/account")
                    || path.starts_with("/password")
                    || path.starts_with("/verify")
                    || path.starts_with("/reset")
                    || path.starts_with("/revoke")
                    || path.starts_with("/update")
                    || path.starts_with("/get-")
            },
        ),
        group(
            "admin",
            "Admin",
            "Privileged user administration",
            registry,
            |path| path.starts_with("/admin"),
        ),
        group(
            "organization",
            "Organizations",
            "Teams, members, invitations, roles",
            registry,
            |path| path.starts_with("/organization"),
        ),
        group(
            "api-key",
            "API keys",
            "Programmatic access tokens",
            registry,
            |path| path.starts_with("/api-key"),
        ),
        group("jwt", "JWT", "Token issuance and JWKS", registry, |path| {
            path.starts_with("/jwt") || path.starts_with("/token") || path.starts_with("/jwks")
        }),
        group(
            "oauth",
            "OAuth / OIDC provider",
            "Authorization server and MCP metadata",
            registry,
            |path| path.starts_with("/oauth2") || path.starts_with("/.well-known"),
        ),
        group(
            "passkey",
            "Passkeys",
            "WebAuthn registration and authentication",
            registry,
            |path| path.starts_with("/passkey"),
        ),
        group(
            "sso",
            "Enterprise SSO",
            "SAML/OIDC federation",
            registry,
            |path| path.starts_with("/sso"),
        ),
        group("scim", "SCIM", "User provisioning", registry, |path| {
            path.starts_with("/scim")
        }),
        group(
            "stripe",
            "Stripe billing",
            "Subscriptions and customer portal",
            registry,
            |path| path.starts_with("/stripe"),
        ),
        group(
            "2fa",
            "Two-factor",
            "TOTP and backup codes",
            registry,
            |path| path.starts_with("/two-factor"),
        ),
        group(
            "phone",
            "Phone number",
            "SMS verification flows",
            registry,
            |path| path.starts_with("/phone-number"),
        ),
        group(
            "device",
            "Device authorization",
            "OAuth device code grant",
            registry,
            |path| path.starts_with("/device"),
        ),
        group(
            "misc-plugins",
            "Other plugins",
            "Anonymous, bearer, magic link, SIWE, …",
            registry,
            |path| {
                path.starts_with("/anonymous")
                    || path.starts_with("/bearer")
                    || path.starts_with("/magic-link")
                    || path.starts_with("/email-otp")
                    || path.starts_with("/one-time-token")
                    || path.starts_with("/siwe")
                    || path.starts_with("/username")
                    || path.starts_with("/multi-session")
                    || path.starts_with("/oauth-proxy")
                    || path.starts_with("/one-tap")
            },
        ),
    ];

    let covered: std::collections::HashSet<String> = groups
        .iter()
        .flat_map(|group| group.endpoints.iter().map(|endpoint| endpoint.path.clone()))
        .collect();

    let uncategorized: Vec<EndpointView> = registry
        .iter()
        .filter(|endpoint| !covered.contains(&endpoint.path))
        .map(endpoint_view)
        .collect();

    if !uncategorized.is_empty() {
        groups.push(EndpointGroup {
            id: "uncategorized".to_owned(),
            label: "Uncategorized".to_owned(),
            description: "New or plugin-specific routes not yet classified".to_owned(),
            endpoints: uncategorized,
        });
    }

    groups.retain(|group| !group.endpoints.is_empty());
    groups
}

fn group<F>(
    id: &str,
    label: &str,
    description: &str,
    registry: &[EndpointInfo],
    matcher: F,
) -> EndpointGroup
where
    F: Fn(&str) -> bool,
{
    EndpointGroup {
        id: id.to_owned(),
        label: label.to_owned(),
        description: description.to_owned(),
        endpoints: registry
            .iter()
            .filter(|endpoint| matcher(endpoint.path.as_str()))
            .map(endpoint_view)
            .collect(),
    }
}

pub fn endpoint_views(registry: &[EndpointInfo]) -> Vec<EndpointView> {
    registry.iter().map(endpoint_view).collect()
}

fn endpoint_view(endpoint: &EndpointInfo) -> EndpointView {
    EndpointView {
        method: endpoint.method.as_str().to_owned(),
        path: endpoint.path.clone(),
        kind: format!("{:?}", endpoint.kind),
        operation_id: endpoint.operation_id.clone().unwrap_or_default(),
        media_types: endpoint.allowed_media_types.clone(),
    }
}
