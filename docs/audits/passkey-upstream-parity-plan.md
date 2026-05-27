# Passkey Upstream Parity Audit Plan

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/passkey/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/routes.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/client.ts`
- `upstream/better-auth/1.6.9/repository/packages/passkey/src/passkey.test.ts`
- `upstream/better-auth/1.6.9/repository/docs/content/docs/plugins/passkey.mdx`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/middlewares/authorization.ts`

## OpenAuth Files Inspected

- `crates/openauth-passkey/src/lib.rs`
- `crates/openauth-passkey/src/options.rs`
- `crates/openauth-passkey/src/schema.rs`
- `crates/openauth-passkey/src/routes.rs`
- `crates/openauth-passkey/src/routes/registration.rs`
- `crates/openauth-passkey/src/routes/authentication.rs`
- `crates/openauth-passkey/src/routes/management.rs`
- `crates/openauth-passkey/src/store.rs`
- `crates/openauth-passkey/src/webauthn.rs`
- `crates/openauth-passkey/src/challenge.rs`
- `crates/openauth-passkey/src/cookies.rs`
- `crates/openauth-passkey/src/session.rs`
- `crates/openauth-passkey/src/openapi.rs`
- `crates/openauth-passkey/src/response.rs`
- `crates/openauth-passkey/tests/passkey/*`

## Confirmed Matches

- Endpoint set matches upstream server endpoints:
  `generate-register-options`, `generate-authenticate-options`,
  `verify-registration`, `verify-authentication`, `list-user-passkeys`,
  `delete-passkey`, and `update-passkey`.
- Challenge state is server-side, referenced by a signed
  `better-auth-passkey` cookie, and expires after 5 minutes.
- Registration supports the upstream default authenticated-session flow and
  pre-auth flow with `require_session(false)`, `resolve_user`, `context`,
  registration extensions, and `after_verification`.
- Authentication supports discoverable credentials, session-scoped
  allow-credentials generation, authentication extensions,
  `after_verification`, session creation, counter/state updates, and challenge
  deletion.
- Management endpoints require a session and enforce passkey ownership.
- OpenAuth intentionally uses Rust/OpenAuth adapter conventions internally:
  snake_case DB fields, a plural physical table, and a hidden JSON field for
  complete `webauthn-rs` credential state.

## Confirmed Differences

- Public passkey JSON and OpenAPI expose `credentialId`; upstream exposes
  `credentialID`.
- Invalid `authenticatorAttachment` query values are silently ignored;
  upstream request validation rejects invalid enum values.
- Verification currently falls back to `base_url` or localhost if neither
  `PasskeyOptions.origin` nor an `Origin` request header exists. Upstream
  verification requires an explicit configured origin or request `Origin`.
- Update/delete return `400 PASSKEY_NOT_FOUND` when a passkey is missing.
  Upstream `requireResourceOwnership` returns `404`.
- Delete-by-non-owner uses the registration ownership error code. Upstream
  delete uses generic unauthorized for ownership failures, while update uses
  the custom passkey ownership message.
- The real WebAuthn backend uses a stable UUID user handle. Upstream generates
  a new random user handle for each registration ceremony.
- The real WebAuthn backend stores `aaguid` as `None` even when attestation
  metadata exposes one.
- `verify-registration` did not require an authenticated session when
  `require_session` is enabled. Upstream applies `freshSessionMiddleware` to
  the verification endpoint in the default registration flow.
- The real WebAuthn backend stored `publicKey` as base64 JSON bytes for the
  internal `webauthn-rs` COSE key shape. Upstream stores base64 COSE public-key
  CBOR bytes.

## Risks

- Renaming `credentialId` to `credentialID` is a public JSON compatibility
  change for current OpenAuth beta users, but it aligns the server contract
  with Better Auth.
- Requiring an explicit verification origin may break direct server-to-server
  tests or clients that omit the `Origin` header. Existing tests should either
  set `Origin` or configure `PasskeyOptions::origin`.
- Random user handles improve upstream parity, but existing authenticators
  will see each registration ceremony as independent. That matches upstream
  behavior and does not change stored OpenAuth user ownership.

## Proposed Fixes

- Rename only serialized/OpenAPI passkey response fields from `credentialId`
  to `credentialID`; keep Rust field and DB column names unchanged.
- Reject invalid `authenticatorAttachment` query values with a `400` JSON
  error instead of ignoring the value.
- Add verification-specific WebAuthn config construction that uses configured
  origins or the request `Origin` header and fails when neither exists.
- Return `404 PASSKEY_NOT_FOUND` for missing passkeys in update/delete.
- Return generic `401 UNAUTHORIZED` for delete-by-non-owner while keeping the
  upstream custom unauthorized error for update-by-non-owner.
- Use a fresh random UUID for real registration user handles.
- Extract `aaguid` from `webauthn-rs` `AttestationMetadata::Packed` and
  `AttestationMetadata::Tpm` when present.
- Require an authenticated session before verifying registration when
  `RegistrationOptions::require_session` is enabled.
- Encode real-registration `publicKey` as COSE public-key CBOR before base64
  storage, while keeping the hidden `webauthn_credential` state unchanged.
- Add crate-local parity documentation under
  `crates/openauth-passkey/UPSTREAM_PARITY.md`.

## Tests To Add Or Update

- Assert public registration/list/OpenAPI response fields use `credentialID`.
- Assert invalid `authenticatorAttachment` returns `400`.
- Assert verification without configured origin and without `Origin` fails.
- Update happy-path verification tests to include `Origin` or configured
  origin.
- Assert missing update/delete targets return `404 PASSKEY_NOT_FOUND`.
- Assert delete-by-non-owner returns generic `401 UNAUTHORIZED`.
- Assert real backend registration generates different user handles for the
  same OpenAuth user across registration ceremonies.
- Add focused helper coverage for extracting AAGUID from Packed/TPM metadata if
  test construction is feasible without broad fixtures.
- Assert `verify-registration` returns `401 SESSION_REQUIRED` without a
  session in the default registration flow.
- Assert real backend `publicKey` output decodes as a COSE CBOR map with the
  expected algorithm, key type, curve, and coordinate fields.
- Assert registration and authentication challenge expiration is computed per
  request.

## Intentionally Left Unchanged

- The hidden `webauthn_credential` JSON field remains; it is necessary for
  secure `webauthn-rs` authentication state and counter/backup-state updates.
- The extra OpenAuth check that rejects a credential outside a session-scoped
  authentication challenge remains as a security hardening over upstream.
- The physical schema remains plural/snake_case to match OpenAuth adapter
  conventions; public JSON/OpenAPI preserves upstream field names.
