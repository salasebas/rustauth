# openauth-oidc

Enterprise OIDC relying-party support for OpenAuth.

Use this crate when OpenAuth consumes external OIDC identity providers such as
Okta, Microsoft Entra ID, Auth0, Google Workspace, or Keycloak. This is not the
OpenAuth OAuth/OIDC provider implementation; authorization-server behavior lives
in `openauth-oauth-provider`.

This crate intentionally has no SAML, XML signature, XML encryption, `samael`,
`openssl`, or `xmlsec` dependency surface.
