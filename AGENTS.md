# RustAuth Agent Guide

RustAuth is an unofficial Rust implementation inspired by Better Auth, not a
line-by-line port. For new features, behavior changes, tests, or public APIs,
use the upstream snapshot in `reference/upstream-better-auth/VERSION.md` as the
behavioral reference. Upstream source lives under
`reference/upstream-src/<parity-version>/repository/` and is gitignored; fetch it
with `./scripts/fetch-upstream-better-auth.sh` if missing. Do not commit
upstream clones.

Translate behavior into idiomatic Rust with explicit errors, focused modules,
and secure server-side boundaries. Discover crate ownership from `Cargo.toml`,
`crates/*/README.md`, and the existing source tree instead of duplicating repo
structure here.

The primary implementation crates are `rustauth-*`. The `rustauth` crate is a
thin backward-compatibility re-export shim (`pub use rustauth::*`).

## Deliverables

Before finishing code changes, run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run -p <touched-crate> --all-features
```

- **fmt + clippy**: always, full workspace (same as CI).
- **tests**: at minimum, every crate you changed, with `--all-features` unless CI uses different flags (see `.github/workflows/ci.yml`; e.g. `rustauth-sqlx` uses `--features sqlite`).
- **broader pass**: if the change crosses crates or touches shared APIs, run nextest on each affected crate from the CI matrix — not `cargo nextest run --workspace` unless you need a full local sweep.
- **Docker / `#[ignore]` tests**: only when you touch adapters, rate limits, or live storage; start services with `./scripts/ensure-test-services.sh`.

If you skipped any gate, say what and why. Do not call work merge-ready without verification.

For security-sensitive or user-facing behavior, add focused tests for observable
behavior, validation, serialization, errors, and integration contracts. When
porting from Better Auth, adapt matching upstream test scenarios.

**Outbound email/SMS (OTP, reset, verify):** never `.await` sender hooks before
the HTTP success response. Use [`dispatch_outbound`](crates/rustauth-core/src/outbound.rs)
from core/plugins; integrators implement async senders returning
`OutboundSendFuture`. See [docs/security-outbound-delivery.md](docs/security-outbound-delivery.md).

## Tests

- **Unit tests** in `src/` (`#[cfg(test)]`) for pure logic.
- **`tests/`** for HTTP routes, adapters, and cross-module wiring (separate binaries).
- Slow Docker or e2e tests stay in `tests/` with `#[ignore]` or in `.github/workflows/integration.yml`.
- Reuse `rustauth_core::test_utils` (`test-utils` feature); do not copy fixtures across crates.

## Dependencies

New dependencies are allowed, but propose them before adding them. Prefer
maintained, widely used libraries suitable for authentication or
security-sensitive code, and keep optional integrations behind feature flags.

## Release And Artifacts

For release work, read `RELEASE.md` first.

Use the local workspace `target/` directory by default. Do not delete build
artifacts or `/private/tmp` caches unless explicitly asked.
