# Axum Upstream Parity Audit Plan

## Summary

Target: `crates/openauth-axum`.

Better Auth does not ship an Axum-specific integration. This audit compares
OpenAuth's Axum adapter with Better Auth's generic server handler boundary:
Fetch `Request` to `Response` handling, router base path behavior, Node header
bridging, and the upstream context tests that define `basePath` behavior.

The audit found two adapter-boundary changes justified by upstream behavior:
accept an empty Axum mount base path as a root mount, and infer a request base
URL when `OpenAuthOptions::base_url` is omitted. Better Auth treats
`basePath: ""` the same as `basePath: "/"`; OpenAuth core already normalizes
empty base paths as root for path matching, but `openauth-axum` rejected the
empty string before mounting. Better Auth also derives a base URL from request
headers/URL when a static base URL is not configured; OpenAuth now does the
same through a framework-neutral request extension populated by the Axum
adapter.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/auth/base.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/index.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/integrations/node.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/utils/url.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/context/create-context.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/utils/get-request-ip.ts`

## OpenAuth Files Inspected

- `crates/openauth-axum/src/router.rs`
- `crates/openauth-axum/src/request.rs`
- `crates/openauth-axum/src/response.rs`
- `crates/openauth-axum/src/error.rs`
- `crates/openauth-axum/src/options.rs`
- `crates/openauth-axum/tests/social.rs`
- `crates/openauth-axum/tests/email_verification.rs`
- `crates/openauth-axum/tests/password.rs`
- `crates/openauth-axum/tests/routing.rs`
- `crates/openauth-axum/tests/body_limit.rs`
- `crates/openauth-axum/tests/error_contract.rs`
- `crates/openauth-core/src/api/endpoint.rs`
- `crates/openauth-core/src/api/router.rs`
- `crates/openauth-core/src/api/path.rs`
- `crates/openauth-core/src/utils/url.rs`

## Confirmed Matches

- Axum routes forward all methods to the framework-neutral OpenAuth router.
- Responses preserve status, version, headers, duplicate headers, extensions,
  and body bytes.
- Invalid adapter/body collection errors are converted into JSON errors.
- Core route matching, media type validation, CSRF/origin validation, plugin
  hooks, and rate limiting stay in `openauth-core`.
- The upstream `skipTrailingSlashes` behavior is implemented by core and now
  covered through the Axum adapter mount.
- `ConnectInfo` IP propagation is an intentional secure Rust adapter addition
  that avoids trusting spoofable forwarding headers by default.
- Public URLs generated during OAuth, email verification, and password reset can
  use a request-derived base URL when no static `base_url` is configured.

## Confirmed Differences

- Better Auth treats `basePath: ""` as equivalent to root. `openauth-axum`
  rejected `""` as `InvalidBasePath` before mounting, even though core URL
  normalization already handles an empty base path as root.
- Better Auth infers base URL from the request when no static base URL is
  configured. OpenAuth previously left `context.base_url` empty, producing
  incomplete generated URLs and preventing relative callback URLs from passing
  request-origin validation in host-derived deployments.

## Risks

- Accepting `""` must not weaken Axum route safety for non-empty paths. The
  adapter must continue rejecting non-absolute non-empty paths and Axum pattern
  syntax such as `{}`, `*`, query strings, and fragments.
- A root mount catches all nested auth paths at the application root, so callers
  should use it intentionally. This matches upstream behavior for an empty or
  root base path.
- Request-derived base URL must not blindly trust public proxy headers. The Axum
  adapter therefore uses `Host`/absolute URI by default and only honors
  `x-forwarded-host` plus `x-forwarded-proto` when
  `OpenAuthAxumOptions::trust_proxy_headers_for_base_url(true)` is set.

## Proposed Fixes

- Normalize `""` to `"/"` in `crates/openauth-axum/src/router.rs`.
- Keep rejecting `api/auth`, `/api/{auth}`, `/api/*auth`,
  `/api/auth?x=1`, and `/api/auth#x`.
- Add integration coverage proving `OpenAuth::builder().base_path("")` serves
  `/ok` through Axum.
- Update the README notes to document that `base_path("/")` and `base_path("")`
  mount at the application root.
- Add a framework-neutral `RequestBaseUrl` extension and populate it in
  `openauth-axum` when `base_url` is omitted.
- Use the request base URL for OAuth redirect URIs, callback-origin validation,
  verification emails, and password reset emails.
- Add explicit opt-in proxy header support for base URL inference.

## Tests To Add Or Update

- Update the router unit test so `normalize_base_path("") == "/"`.
- Remove `""` from the invalid base path integration cases.
- Add an Axum routing integration test for empty base path root mounting.
- Add an Axum routing integration test for upstream `skipTrailingSlashes`
  behavior.
- Add Axum tests for host-derived OAuth redirect URIs, opt-in trusted proxy
  header behavior, verification email URLs, and password reset URLs.
- Run:
  - `cargo fmt --all --check`
  - `cargo clippy -p openauth-core --all-targets -- -D warnings`
  - `cargo clippy -p openauth --all-targets -- -D warnings`
  - `cargo clippy -p openauth-axum --all-targets -- -D warnings`
  - `cargo nextest run -p openauth-core`
  - `cargo nextest run -p openauth`
  - `cargo nextest run -p openauth-axum`

## Server-Side Parity Estimate

Estimated Axum adapter parity with Better Auth's server-side handler boundary:
**97%**.

Covered:

- Request handoff into the framework-neutral router.
- Base path default, custom path, root path, empty root path, and trailing slash
  routing behavior.
- Method dispatch, not-found behavior, media type validation, JSON and
  form-urlencoded request parsing through core.
- Response status, version, duplicate headers, extensions, empty bodies, and
  body bytes.
- Origin/CSRF/fetch metadata security, callback URL validation, rate limiting,
  and IP source selection.
- Request-derived base URL for generated public URLs, with secure default
  handling for proxy headers.

Remaining gaps are mostly broader OpenAuth core parity, not Axum adapter gaps:

- Better Auth `onAPIError.throw`/custom error callback semantics do not have a
  one-for-one Axum adapter surface; OpenAuth currently sanitizes internal
  adapter-boundary errors.
- Better Auth's runtime is Fetch/Node-native and can stream bodies. The Axum
  adapter intentionally buffers request and response bodies into `Vec<u8>` with
  a size cap.
- Some upstream plugin/package server behavior is outside `openauth-axum` and
  must be audited per plugin crate.

## Intentionally Left Unchanged

- Keep the Axum body limit option and default 10 MiB cap as adapter-level
  production hardening.
- Keep ignoring spoofable forwarding headers unless OpenAuth core is explicitly
  configured for trusted IP headers.
- Keep internal OpenAuth errors sanitized at the adapter boundary.
- Do not change database schema, query behavior, feature flags, or unrelated
  public re-exports.
