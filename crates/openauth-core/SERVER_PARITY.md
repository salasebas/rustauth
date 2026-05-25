# OpenAuth Core Server Parity Notes

This file records server-side Better Auth parity decisions for `openauth-core`.
It is intentionally separate from the crate README.

## Completed

- Social OAuth implicit account linking now follows the central
  `handle_oauth_user_info` policy across authorization-code callbacks and
  `idToken` sign-in:
  - existing same-email users link when the provider email is verified;
  - unverified provider emails require the provider to be listed in
    `account.account_linking.trusted_providers`;
  - `disable_implicit_linking` and disabled account linking still fail closed.
- Explicit link-account flows keep the existing email-match and
  `allow_different_emails` behavior.

## Intentional Rust/OpenAuth Differences

- OpenAuth uses static `trusted_providers: Vec<String>` configuration instead
  of Better Auth's JavaScript `trustedProviders` array-or-function union. A
  request-scoped dynamic resolver would require a public Rust callback API and
  should be designed separately.
- Error responses keep OpenAuth's typed JSON/redirect conventions rather than
  duplicating every Better Auth string shape where the observable security
  behavior is equivalent.

## Remaining Server-Side Risk

- If applications need tenant- or request-dependent trusted providers, they
  currently need to construct separate `AuthContext` values or wait for a
  dedicated dynamic trusted-provider API.
