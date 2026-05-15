# OAuth Proxy Final Checklist

- [x] Merge local `main` into `feat/oauth-proxy-plugin`.
- [x] Resolve merge conflicts preserving `main` additions and OAuth proxy dependencies.
- [x] Add failing tests for final upstream parity gaps.
- [x] Support upstream cloud env names for current URL.
- [x] Require and validate `/oauth-proxy-callback?callbackURL=...`.
- [x] Bind encrypted `state_cookie` to the original OAuth state and reject mismatch.
- [x] Use production base URL for production callback token exchange redirect URI.
- [x] Read `user` from query or form body in callback.
- [x] Keep OAuth proxy modules and `social.rs` within target size.
- [x] Run focused and workspace verification.
- [x] Commit robustness changes.
- [x] Merge `feat/oauth-proxy-plugin` into local `main`.
- [x] Run post-merge verification on `main`.
