# openauth-stripe

Stripe integration surface for OpenAuth-RS.

## Status

This package is in experimental beta and currently exposes the package surface
while Stripe behavior is being built out. Public APIs may change before stable
release.

## What It Provides

`openauth-stripe` is reserved for server-side Stripe billing and webhook
integration. The intended scope is billing-aware authentication behavior,
webhook verification, subscription state, and storage contracts owned by
OpenAuth-RS.

## Example

```rust
let stripe_crate_version = openauth_stripe::VERSION;
```

Keep Stripe-facing implementation behind this crate so the core authentication
path does not require billing dependencies.

## Client SDK Scope

The Better Auth Stripe package includes a browser client helper. OpenAuth keeps
this crate server-side only: future client SDKs should be thin wrappers around
the HTTP endpoints exposed by this plugin, not browser-only logic ported into
the Rust core.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
