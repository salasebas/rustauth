# RustAuth

In this Rust workspace:

- Crate names are prefixed with `rustauth-`; primary crates live under
  `crates/rustauth-*`.
- `crates/rustauth` is the compatibility facade. Keep it a thin re-export layer
  unless the task is explicitly about packaging, docs, or facade API.
- Use `Cargo.toml`, `crates/*/README.md`, and nearby source/tests to discover
  crate ownership before adding modules.
- The workspace forbids unsafe code.

## Working Rules

- Read nearby code and tests before changing behavior.
- Prefer existing module boundaries, naming, error styles, and feature flags.
- Keep diffs focused. Do not mix docs cleanup, behavior changes, and dependency
  upgrades unless the task asks for it.
- Use `rg` / `rg --files` for searches.
- Preserve user changes in the worktree and work around them.
- Do not commit upstream clones, generated trees, build artifacts, or local
  caches.
- Do not create small helper methods used only once.
- If a non-mechanical change grows large, split it into the smallest coherent
  stages.

## Upstream Reference

- For parity or porting work, inspect
  `reference/upstream-src/<version>/repository/` first.
- The active Better Auth version is in
  `reference/upstream-better-auth/VERSION.md`.
- If the expected upstream file is missing, search the local workspace for the
  equivalent behavior. If neither exists, stop and report the missing reference.
- Fetch the pinned upstream source only when needed:

  ```bash
  ./scripts/fetch-upstream-better-auth.sh
  ```

- Treat Better Auth as a behavioral reference, not a line-by-line port. Add a
  focused Rust test for observable behavior before or with the implementation.

## Rust Style

- Prefer private modules and explicitly exported public crate API.
- Prefer explicit `Result` errors over panics.
- `unwrap_used`, `expect_used`, and `panic` are workspace `warn` lints; under
  `-D warnings` they fail builds, including tests.
- Inline format arguments when possible: `format!("{value}")`.
- Collapse nested `if` statements when clear.
- Prefer method references over redundant closures.
- Avoid boolean or ambiguous `Option` parameters in public/auth flow APIs. Use
  enums, typed options, named builders, or newtypes when they make call sites
  clearer.
- If an opaque positional literal is unavoidable, add an exact argument comment,
  for example `foo(/*enabled*/ false)`.
- Make `match` statements exhaustive where practical; avoid wildcard arms when a
  new variant should force review.
- Public traits need doc comments explaining their role and implementation
  expectations.
- Avoid `#[async_trait]` and `#[allow(async_fn_in_trait)]` in new public traits
  when a native return-position future can express the contract.
- Use structured parsers/helpers for tokens, URLs, JSON, XML, headers, and
  database values instead of ad hoc string parsing.
- Avoid growing large modules. Prefer focused modules, especially once a file is
  roughly 800 LoC or larger.

## Tests

- Unit tests for pure logic live near the code under `src/`.
- HTTP routes, adapters, and cross-module wiring belong in `tests/`.
- Reuse `rustauth_core::test_utils` with the `test-utils` feature. Do not copy
  fixtures across crates.
- In tests, return `Result<(), Box<dyn std::error::Error>>` and use `?` instead
  of `.unwrap()` / `.expect()`.
- Prefer comparing whole objects over asserting field by field.
- Do not add tests for values that are statically defined.
- Do not add negative tests for logic that was removed.
- Avoid test-only helpers in implementation modules.

## Security-Sensitive Areas

Be especially conservative when changing sessions, cookies, CSRF, OAuth/OIDC,
SSO, SAML, SCIM, passkeys, tokens, passwords, signing, encryption, redirects,
callbacks, issuer/audience/origin/domain checks, rate limits, storage adapters,
migrations, or transactional behavior.

Keep security-sensitive validation fail-closed. Missing, malformed, expired,
unsigned, or untrusted inputs should produce explicit errors where practical.

Outbound sender hooks for OTP, reset, verify, email, or SMS must not be awaited
before the HTTP success response. Use `dispatch_outbound` from
`crates/rustauth-core/src/outbound.rs`; integrators return `OutboundSendFuture`.

Add regression tests for security fixes.

## Checks

For code changes, run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run -p <touched-crate> --all-features
```

- Use CI flags when they differ; for example, `rustauth-sqlx` uses
  `--features sqlite`.
- Run nextest for each touched crate. Use broader checks when touching shared
  APIs, workspace features, adapters, or cross-crate behavior.
- Run Docker or `#[ignore]` tests only when touching adapters, rate limits, or
  live storage; start services with `./scripts/ensure-test-services.sh`.
- For docs-only changes, cargo checks are usually unnecessary; say they were
  skipped because no Rust code changed.

## Dependencies And Releases

- Do not add dependencies without proposing them first.
- Prefer maintained, widely used crates suitable for authentication or
  security-sensitive code.
- Keep optional integrations behind feature flags.
- If `Cargo.toml` changes, include the matching `Cargo.lock` update when needed.
- For release work, read `RELEASE.md` first.
- Keep README/docs claims aligned with `CHANGELOG.md`, crate features, and the
  active upstream pin.
- Do not hardcode future release versions in docs.
- Do not delete build artifacts, `target/`, or `/private/tmp` caches unless
  explicitly asked.
