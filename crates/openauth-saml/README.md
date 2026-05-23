# openauth-saml

SAML 2.0 service-provider support for OpenAuth enterprise SSO.

This crate contains SAML AuthnRequest generation, SP metadata, ACS parsing,
SLO helpers, assertion extraction, XML hardening, timestamp and algorithm policy
validation, and replay-state key helpers.

Signed and encrypted SAML messages currently fail closed unless explicit backend
support is added behind a feature. The `saml-signed` feature reserves that
surface; this refactor does not add `xmlsec1`, `samael`, `openssl`, or any new
signature backend dependency.
