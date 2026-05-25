# OpenAPI, Organization, Phone Number, and SIWE Upstream Parity Audit Plan

## Summary

Audit the server-side OpenAuth implementations of `open_api`, `organization`,
`phone_number`, and `siwe` against Better Auth 1.6.9, then implement only the
high-confidence parity fixes that preserve idiomatic Rust APIs and explicit
error handling.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/open-api/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/open-api/generator.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/open-api/open-api.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/phone-number/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/phone-number/routes.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/phone-number/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/phone-number/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/phone-number/phone-number.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/siwe/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/siwe/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/siwe/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/siwe/siwe.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/organization.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/has-permission.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/permission.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/routes/*.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/*.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/organization/routes/*.test.ts`

## OpenAuth Files Inspected

- `crates/openauth-core/src/api/openapi.rs`
- `crates/openauth-plugins/src/open_api/mod.rs`
- `crates/openauth-plugins/src/phone_number/**`
- `crates/openauth-plugins/src/siwe/**`
- `crates/openauth-plugins/src/organization/**`
- `crates/openauth-plugins/tests/open_api/mod.rs`
- `crates/openauth-plugins/tests/phone_number/**`
- `crates/openauth-plugins/tests/siwe/**`
- `crates/openauth-plugins/tests/organization/**`

## Confirmed Matches

- Plugin IDs, public constructors, main endpoint paths, error-code catalogs,
  and rate-limit registration match the upstream server-side intent.
- Phone-number OTP storage, expiration, allowed-attempt tracking, duplicate
  phone checks, and unsafe `update-user` blocking are aligned.
- SIWE nonce generation, checksum normalization, chain-scoped identifiers,
  nonce deletion after success, anonymous email generation, ENS metadata,
  wallet table shape, and multi-chain wallet linking are aligned.
- Organization core lifecycle, permissions, invitations, teams, hooks, dynamic
  roles, returned-field filtering, active organization/session fields, and
  schema contributions are broadly aligned.
- Rust intentionally keeps richer OpenAuth error bodies with `code`, `message`,
  and sometimes `originalMessage`; do not reduce them to upstream's simpler
  OpenAPI error schema.

## Confirmed Differences

- OpenAPI component schemas are static and miss runtime plugin tables and
  additional fields; some optional fields still use OpenAPI 3.0-style
  `nullable` instead of OpenAPI 3.1 type arrays.
- Phone-number `verify` with `updatePhoneNumber` returns `token: null`; upstream
  returns the current session token.
- Phone-number custom `verifyOTP` success does not delete an existing internal
  verification record; upstream deletes it.
- Phone-number sign-up-on-verification ignores user additional fields from the
  verify request body; upstream passes remaining body fields through user input
  parsing.
- Phone-number password reset does not invoke `password.on_password_reset` or
  revoke sessions when configured; upstream and OpenAuth email-OTP reset do.
- Organization `get-full-organization`, `list-members`, and
  `get-active-member-role` are active-organization-only; upstream accepts
  `organizationId`/`organizationSlug`, supports `membersLimit`, member
  pagination/filter/sort, `total`, and querying another member's role after
  verifying requester membership.
- SIWE verifier and ENS callback errors propagate as explicit Rust errors,
  whereas upstream wraps unexpected SIWE errors as a generic 401.

## Proposed Fixes

- Build OpenAPI component schemas from `AuthContext::db_schema.tables()` and
  emit OpenAPI 3.1 nullable types for optional fields.
- Preserve OpenAuth-specific operation metadata, response shape, paths, and
  error response schema.
- Return the current session token from phone-number update verification.
- Delete internal phone OTP rows after successful custom verifier calls.
- Parse user additional fields from phone verification requests and persist
  them during sign-up-on-verification.
- Mirror email-OTP reset behavior for phone password reset callbacks and
  session revocation.
- Add upstream-compatible organization query handling for full organization,
  member listing, and active member role lookup.

## Tests To Add Or Update

- OpenAPI: dynamic user additional fields, plugin component schemas, and
  OpenAPI 3.1 optional field nullability.
- Phone-number: update verification token, custom verifier cleanup,
  sign-up-on-verification additional fields, password-reset callback, and
  password-reset session revocation.
- Organization: full organization by id/slug and no-active null response,
  member list by id/slug with limit/offset/filter/sort and total, non-member
  forbidden responses, and active member role lookup by user id.

## Risks

- Dynamic OpenAPI schemas may alter downstream schema snapshots. Keep endpoint
  operation IDs and OpenAuth error response shapes stable.
- Organization query filtering must map only supported query operators to avoid
  silently accepting unsupported semantics.
- Phone-number additional field parsing must reuse core user additional-field
  validation so hidden/generated fields remain protected.

## Intentionally Left Unchanged

- Do not convert sync phone/organization callbacks to async in this pass; that
  would be a public API migration.
- Do not expose `list-user-invitations?email=` over public HTTP because upstream
  treats email override as server-side-only and OpenAuth has no equivalent
  private server-call boundary here.
- Do not wrap SIWE verifier/ENS callback failures as generic 401 responses;
  Rust callers currently get explicit `OpenAuthError` propagation.
