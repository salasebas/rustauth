# JWT Final Parity Checklist

- [x] Merge `main` into `feat/jwt-plugin`.
- [x] Implement server-side JWT plugin under `crates/openauth-plugins`.
- [x] Add private key encryption, async callbacks, custom adapter, rotation, remote URL handling, and session JWT header hook.
- [x] Keep JWT implementation and tests split into focused files below the review-size threshold.
- [x] Add final parity tests for server-only endpoints, request state, explicit verification options, malformed key cases, remote URL local signing, RSA modulus validation, custom adapter JWKS creation, and wrong-secret decrypt failures.
- [x] Run final validation commands.
- [x] Split into core and plugin commits.
- [x] Merge latest local `main`.
