# Passkey Upstream Parity

This document records server-side parity decisions for `openauth-passkey`
against Better Auth's passkey plugin.

## Status

Server-side parity is considered complete for the current OpenAuth architecture.
Estimated parity: **98%**.

The remaining differences are either client/TypeScript-only concerns or
intentional Rust/OpenAuth architecture choices that preserve the observable
server contract.

## Upstream Behavior Matched

- Server endpoints match the upstream passkey endpoint set:
  `generate-register-options`, `generate-authenticate-options`,
  `verify-registration`, `verify-authentication`, `list-user-passkeys`,
  `delete-passkey`, and `update-passkey`.
- Challenge state is stored server-side, referenced by the
  `better-auth-passkey` signed cookie, and expires per request after 5 minutes.
- Registration supports authenticated sessions, pre-auth `resolve_user`,
  `context`, extensions, fresh-session checks, `after_verification`, duplicate
  credential rejection, and challenge cleanup.
- `verify-registration` requires a session by default, matching upstream
  `freshSessionMiddleware`.
- Verification origin behavior matches upstream: verification requires either
  configured `PasskeyOptions::origin` or a request `Origin` header.
- Authentication supports discoverable credentials, session-scoped
  allow-credentials, extensions, `after_verification`, session creation,
  counter/state updates, and challenge cleanup.
- Public passkey JSON/OpenAPI uses upstream `credentialID`.
- Stored `publicKey` for real WebAuthn registrations is base64-encoded COSE
  public-key CBOR, matching upstream's `credential.publicKey` storage contract.
- Missing passkey update/delete targets return `404 PASSKEY_NOT_FOUND`.
- Update/delete ownership behavior matches upstream's observable distinction:
  update returns the passkey ownership error, delete returns generic
  unauthorized.
- Real WebAuthn registration uses a fresh random user handle per ceremony.
- AAGUID is extracted from supported attestation metadata.

## Intentional Rust/OpenAuth Differences

- The physical database table defaults to `passkeys` and fields are snake_case.
  Better Auth's logical model is `passkey` with camelCase fields. OpenAuth keeps
  Rust/adapter naming conventions while serializing public responses in the
  upstream shape.
- OpenAuth stores a hidden `webauthn_credential` JSON field. This is required
  to persist complete `webauthn-rs` credential state for secure authentication,
  counter updates, backup-state updates, and future library compatibility.
- OpenAuth keeps a stricter session-scoped authentication challenge check:
  credentials outside a session-scoped challenge are rejected even if upstream
  would rely only on credential lookup.
- Error handling intentionally favors explicit Rust errors over upstream's broad
  `try/catch` behavior in a few failure paths. Observable security boundaries
  and documented error codes are preserved where they matter.

## Out Of Scope

- Better Auth client helpers, browser `startRegistration`/`startAuthentication`
  behavior, nanostores, and TypeScript inference helpers are client-side only.
- Better Auth OpenAPI metadata text and generated TypeScript-specific schema
  details are not copied line-by-line when they do not affect server behavior.
