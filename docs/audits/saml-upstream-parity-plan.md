# SAML Upstream Parity Audit Plan

## Summary

Audit found `crates/openauth-saml` is largely aligned for structural assertion
counting, timestamp checks, algorithm constants, runtime algorithm validation,
XML local-name handling, and fail-closed signature/decryption placeholders.
Three justified parity fixes should be made: accept a single encrypted assertion
in `validate_single_assertion`, preserve upstream SAML config wire names like
`entityID`, and prefer HTTP-Redirect when normalizing IdP SSO services for
redirect AuthnRequests.

## Files Inspected

Upstream Better Auth files inspected:

- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml/assertions.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml/algorithms.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml/parser.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml/timestamp.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml-state.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/routes/saml-pipeline.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/routes/helpers.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/routes/sso.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/routes/providers.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml/assertions.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/sso/src/saml/algorithms.test.ts`
- `upstream/better-auth/1.6.9/repository/e2e/smoke/test/saml.spec.ts`

OpenAuth files inspected:

- `crates/openauth-saml/src/options.rs`
- `crates/openauth-saml/src/saml/assertions.rs`
- `crates/openauth-saml/src/saml/authn_request.rs`
- `crates/openauth-saml/src/saml/encryption.rs`
- `crates/openauth-saml/src/saml/logout.rs`
- `crates/openauth-saml/src/saml/metadata.rs`
- `crates/openauth-saml/src/saml/security.rs`
- `crates/openauth-saml/src/saml/signature.rs`
- `crates/openauth-saml/src/saml/state.rs`
- `crates/openauth-saml/src/saml/xml.rs`
- `crates/openauth-saml/tests/security.rs`
- `crates/openauth-sso/src/routes/saml_config.rs`
- `crates/openauth-sso/src/routes/saml_acs.rs`
- `crates/openauth-sso/src/routes/sign_in.rs`
- `crates/openauth-sso/src/routes/saml_metadata.rs`
- `crates/openauth-sso/src/options.rs`
- `crates/openauth-sso/tests/sso/endpoints/saml/metadata_acs/validation.rs`

## Confirmed Matches

- Algorithm URI constants match upstream.
- Config algorithm validation accepts URI and short-form names and supports
  allow lists.
- Runtime validation is intentionally at least as strict as upstream.
- Base64 whitespace normalization matches upstream.
- Assertion counting uses local names and ignores `AssertionConsumerService`.
- Timestamp defaults match upstream: 5 minute skew and timestamps optional by
  default.
- Registration-time IdP metadata size and entry point validation already exists
  in OpenAuth.

## Confirmed Differences

- Upstream `validateSingleAssertion` accepts exactly one encrypted assertion,
  leaving later SAML parsing/decryption to handle it. OpenAuth rejected that
  shape during structural validation.
- Upstream SAML config wire keys use acronym casing such as `entityID`,
  `entityURL`, and `redirectURL`; OpenAuth accepted `entityID` but serialized
  `entityId`, and used camelCase for the URL fields.
- For configured `idpMetadata.singleSignOnService`, OpenAuth selected the first
  valid HTTP URL. Redirect-binding AuthnRequests should prefer HTTP-Redirect
  when present.
- Generated SP SLO metadata listed HTTP-Redirect before HTTP-POST, while
  upstream emits POST first and Redirect second.
- SAML assertions with `AudienceRestriction` were parsed without retaining
  `Audience` values, so ACS validation could not reject an assertion scoped to a
  different SP entity. Better Auth delegates SAML response validation to
  `samlify`, which validates this class of response contract.

## Proposed Fixes

- Let `validate_single_assertion` accept one direct encrypted assertion, while
  keeping parse/decryption paths fail-closed until decryption support exists.
- Serialize upstream-compatible acronym keys and retain legacy aliases for
  deserialization.
- Prefer configured HTTP-Redirect SSO service locations before falling back to
  the first valid configured service.
- Emit generated SP SLO metadata as HTTP-POST then HTTP-Redirect.
- Parse assertion audience restrictions and reject ACS responses whose audience
  list is present but does not contain the configured audience, SP entity ID, or
  issuer fallback.

## Tests To Add Or Update

- Add `validate_single_assertion_accepts_single_encrypted_assertion`.
- Add SAML config serde coverage for upstream acronym output and legacy alias
  input.
- Add generated SP SLO metadata ordering coverage.
- Add SSO registration/sign-in coverage proving POST-first configured SSO
  services still use Redirect for outbound AuthnRequests.
- Add parser and ACS regression coverage for assertion audience restrictions.

## Items Intentionally Left Unchanged

- XMLDSig verification/signing and encrypted assertion decryption remain
  fail-closed placeholders; implementing them requires explicit cryptographic
  dependency review.
- OpenAuth's stricter direct-`Response` assertion placement check remains in
  place as XSW hardening beyond upstream.
- `acs_url` remains a Rust-side improvement over upstream callback URL
  ambiguity.
- Runtime digest/encryption algorithm validation stays stricter than upstream's
  narrower checks.
- Responses without an `AudienceRestriction` remain accepted for IdP
  compatibility; this audit only rejects explicit mismatches.

## Risks

- Stored JSON may begin serializing `entityID` instead of `entityId`; alias
  support keeps deserialization compatible.
- Full upstream parity for signed AuthnRequests, inbound SAML signatures, SLO
  signatures, and encrypted assertions remains future work.

## Remaining Server-Side Parity Estimate

Estimated SAML server-side parity after these fixes: **70%**.

Covered behavior includes request/response routing, provider registration and
storage, AuthnRequest generation for unsigned Redirect flow, SAML response
shape checks, assertion counting, issuer/destination/recipient/InResponseTo
validation, timestamp validation, audience mismatch rejection when restrictions
are present, metadata generation, SLO routing scaffolding, algorithm constants,
config/runtime algorithm policy checks, and upstream-compatible config wire
names.

Material gaps remain for XMLDSig verification, signed AuthnRequests, signed SLO
messages, encrypted assertion decryption, full IdP metadata XML ingestion, and
complete samlify-equivalent XML canonicalization/reference validation.
