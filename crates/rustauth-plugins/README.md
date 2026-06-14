# rustauth-plugins

Official server-side plugin modules for RustAuth.

## What It Is

`rustauth-plugins` groups Better Auth-inspired server features translated into
RustAuth's Rust plugin contracts. Use it when you want optional auth behavior
without pulling each feature into `rustauth-core`.

The deprecated upstream `oidc-provider` and MCP authorization-server plugins are
not implemented here. Use `rustauth-oauth-provider` for OAuth 2.1, OpenID
Connect provider behavior, and MCP protected-resource metadata.

## What It Provides

Current modules include access control, additional fields, admin, anonymous
users, API keys, bearer sessions, CAPTCHA hooks, custom sessions, device
authorization, email OTP, generic OAuth, Have I Been Pwned checks, JWT, last
login method, magic links, multi-session, OAuth proxy, one-tap, one-time
tokens, OpenAPI, organizations, phone number, SIWE, two-factor, and username.

Some plugins are pure helpers. Many require an RustAuth adapter because they
store users, sessions, keys, organizations, tokens, or verification state.

## Quick Start

```rust
use rustauth::RustAuth;
use rustauth_plugins::prelude::*;

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(admin(AdminOptions::default())?)
    .plugin(jwt(JwtOptions::default())?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Import factories from [`prelude`](./src/prelude.rs) when wiring several plugins.
Each plugin exposes one factory: `plugin_name(options)` (or `plugin_name(options)?`
when validation can fail). Dev-only presets such as `magic_link_dev_log()` and
`siwe_dev()` remain for local development.

Register plugins on [`RustAuth::builder()`](../rustauth/README.md):

- `.plugin(x)` — append one plugin (chain as needed).
- `.plugins(vec![...])` — append a batch (same as chaining `.plugin`).

When building [`RustAuthOptions`](../rustauth-core/README.md) directly,
`.plugin(x)` and `.plugins(vec![...])` both append. Use `.set_plugins(vec![...])`
to replace the full list.

```rust
use rustauth::RustAuth;
use rustauth_plugins::prelude::*;

let core = vec![
    admin(AdminOptions::default())?,
    bearer(BearerOptions::default()),
];
let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugins(core)
    .plugin(jwt(JwtOptions::default())?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`email_otp` and `phone_number` resolve the database adapter from the auth
context at runtime; pass the adapter only to `RustAuth::builder().adapter(...)`.

Use module-specific options when a plugin needs application callbacks such as
email sending, OTP delivery, CAPTCHA verification, SIWE verification, or custom
authorization policy.

## Plugin factory conventions

1. **`foo(options)`** — single factory per plugin; always pass an options value
   (`FooOptions::default()` when defaults are valid).
2. **Fallible factories** — return `Result<AuthPlugin, RustAuthError>` when options
   validation can fail (`admin`, `api_key`, `captcha`, `email_otp`, `jwt`, …).
3. **Dev presets** — `magic_link_dev_log()`, `siwe_dev()`, `siwe_dev_domain()` for
   local development only (not general zero-arg factories).

### Configuring options

All three styles are supported and equivalent:

| Style | When to use | Example |
|-------|-------------|---------|
| Struct literal | Full control, small configs | `email_otp(EmailOtpOptions { sender: Some(s), ..Default::default() })?` |
| Builder | Incremental or optional fields | `email_otp(EmailOtpOptions::builder().sender(s).build()?)?` |
| `Options::new(...)` | Required callbacks only | `email_otp(EmailOtpOptions::new(sender))?` |

Callback-required plugins (`email_otp`, `phone_number`, `magic_link`, `captcha`, `siwe`)
also offer `FooOptions::new(...)` or provider helpers such as
`CaptchaOptions::cloudflare_turnstile(secret)`.

Email, SMS, and magic-link senders are **async** — return `OutboundSendFuture`
(`Box::pin(async move { ... })`). RustAuth dispatches delivery in the background;
do not block handlers on SMTP/SMS. See
[docs/security-outbound-delivery.md](../../docs/security-outbound-delivery.md).

```rust
EmailOtpOptions::new(Arc::new(|payload, _req| {
    Box::pin(async move {
        smtp.send(&payload.email, &payload.otp).await?;
        Ok(())
    })
}))
```

Use `RustAuth::builder()` for the auth instance. In `rustauth-core`, prefer
`TypeName::new()` for core option structs (not `Options::builder()` on core types).

## Plugin factory table

| Plugin | Factory | Dev preset |
|--------|---------|------------|
| Additional fields | `additional_fields(AdditionalFieldsOptions)` | — |
| Admin | `admin(AdminOptions)` → `Result` | — |
| Anonymous | `anonymous(AnonymousOptions)` | — |
| API key | `api_key(ApiKeyOptions)` → `Result` | — |
| Bearer | `bearer(BearerOptions)` | — |
| Captcha | `captcha(CaptchaOptions)` → `Result` | — |
| Custom session | `custom_session(CustomSessionOptions, handler)` | — |
| Device authorization | `device_authorization(DeviceAuthorizationOptions)` → `Result` | — |
| Email OTP | `email_otp(EmailOtpOptions)` → `Result` | — |
| Generic OAuth | `generic_oauth(GenericOAuthOptions)` | presets in `generic_oauth/providers/` |
| Have I Been Pwned | `have_i_been_pwned(HaveIBeenPwnedOptions)` (disabled by default) | — |
| JWT | `jwt(JwtOptions)` → `Result` | — |
| Last login method | `last_login_method(LastLoginMethodOptions)` | — |
| Magic link | `magic_link(MagicLinkOptions)` | `magic_link_dev_log()` |
| Multi-session | `multi_session(MultiSessionOptions)` | — |
| OAuth proxy | `oauth_proxy(OAuthProxyOptions)` | — |
| One Tap | `one_tap(OneTapOptions)` | — |
| One-time token | `one_time_token(OneTimeTokenOptions)` | — |
| OpenAPI | `open_api(OpenApiOptions)` | — |
| Organization | `organization(OrganizationOptions)` | — |
| Phone number | `phone_number(PhoneNumberOptions)` → `Result` | — |
| SIWE | `siwe(SiweOptions)` → `Result` | `siwe_dev()` → `Result` |
| Two-factor | `two_factor(TwoFactorOptions)` | — |
| Username | `username(UsernameOptions)` | — |

Enterprise crates (re-exported from `rustauth::prelude` behind features) follow the
same contract: `passkey(PasskeyOptions)`, `sso(SsoOptions)`, `scim(ScimOptions)`,
`stripe(StripeOptions)?`, and `oauth_provider(OAuthProviderOptions)?`. Register
`jwt(JwtOptions)?` before `oauth_provider(...)` when JWT/OIDC signing is required;
use `OAuthProviderOptions::with_external_jwt()` (or `disable_jwt_plugin: true`) to
run without the jwt plugin.

## Time units

Public plugin and core option timeouts use [`time::Duration`](https://docs.rs/time/latest/time/struct.Duration.html).

| Location | Field | Type |
|----------|-------|------|
| `SessionOptions` | `expires_in`, `update_age`, `fresh_age` | `Option<Duration>` |
| `CookieCacheOptions` / `CookieAttributesOverride` | `max_age` | `Option<Duration>` |
| `RateLimitOptions` / `RateLimitRule` | `window` | `Duration` |
| `EmailVerificationOptions` | `expires_in` | `Option<Duration>` |
| `PasswordOptions` | `reset_password_token_expires_in` | `Option<Duration>` |
| `DeleteUserOptions` | `delete_token_expires_in` | `Option<Duration>` |
| `OneTimeTokenOptions` | `expires_in` | `Duration` |
| `ApiKeyRateLimitOptions` | `time_window` | `Duration` (JSON ms via serde) |
| `ApiKeyExpirationOptions` | `default_expires_in` | `Option<Duration>` (JSON seconds via serde) |
| `MagicLinkOptions` / `MagicLinkRateLimit` | `expires_in`, `window` | `Duration` |
| `EmailOtpOptions` | `expires_in` | `Duration` |
| `PhoneNumberOptions` | `expires_in` | `Duration` |
| `OrganizationOptions` | `invitation_expires_in` | `Duration` |
| `TwoFactorOptions` | `two_factor_cookie_max_age`, `trust_device_max_age` | `Duration` |
| `TotpOptions` / `OtpOptions` | `period` | `Duration` |
| `LastLoginMethodOptions` | `max_age` | `Option<Duration>` |
| `AdminOptions` | `default_ban_expires_in`, `impersonation_session_duration` | `Option<Duration>` / `Duration` |
| `OAuthProxyOptions` | `max_age` | `Duration` (JSON `maxAge` seconds via serde) |
| `PasskeyRateLimit` / `PasskeyChallengeRateLimit` | `window` | `Duration` |
| `DeviceAuthorizationOptions` | `expires_in`, `interval` | `Duration` |

HTTP JSON responses such as OAuth `expires_in` remain RFC-defined **seconds** and
are not converted to `Duration`.

## Time units

Public plugin and core option timeouts use [`time::Duration`](https://docs.rs/time/latest/time/struct.Duration.html).

| Location | Field | Type |
|----------|-------|------|
| `SessionOptions` | `expires_in`, `update_age`, `fresh_age` | `Option<Duration>` |
| `CookieCacheOptions` / `CookieAttributesOverride` | `max_age` | `Option<Duration>` |
| `RateLimitOptions` / `RateLimitRule` | `window` | `Duration` |
| `EmailVerificationOptions` | `expires_in` | `Option<Duration>` |
| `PasswordOptions` | `reset_password_token_expires_in` | `Option<Duration>` |
| `DeleteUserOptions` | `delete_token_expires_in` | `Option<Duration>` |
| `OneTimeTokenOptions` | `expires_in` | `Duration` |
| `ApiKeyRateLimitOptions` | `time_window` | `Duration` (JSON ms via serde) |
| `ApiKeyExpirationOptions` | `default_expires_in` | `Option<Duration>` (JSON seconds via serde) |
| `MagicLinkOptions` / `MagicLinkRateLimit` | `expires_in`, `window` | `Duration` |
| `EmailOtpOptions` | `expires_in` | `Duration` |
| `PhoneNumberOptions` | `expires_in` | `Duration` |
| `OrganizationOptions` | `invitation_expires_in` | `Duration` |
| `TwoFactorOptions` | `two_factor_cookie_max_age`, `trust_device_max_age` | `Duration` |
| `TotpOptions` / `OtpOptions` | `period` | `Duration` |
| `LastLoginMethodOptions` | `max_age` | `Option<Duration>` |
| `AdminOptions` | `default_ban_expires_in`, `impersonation_session_duration` | `Option<Duration>` / `Duration` |
| `OAuthProxyOptions` | `max_age` | `Duration` (JSON `maxAge` seconds via serde) |
| `PasskeyRateLimit` / `PasskeyChallengeRateLimit` | `window` | `Duration` |
| `DeviceAuthorizationOptions` | `expires_in`, `interval` | `Duration` |

HTTP JSON responses such as OAuth `expires_in` remain RFC-defined **seconds** and
are not converted to `Duration`.

## Naming conventions

All plugin HTTP JSON request and response bodies use **camelCase** (`userId`,
`emailVerified`, `callbackURL`) for Better Auth parity (0.2.0+). **Protocol
tables** keep RFC field names unchanged: device authorization (`/device/*`),
OAuth provider (`/oauth2/*`, `.well-known/*`), and SCIM v2 (`/scim/v2/*`).

- **Database logical names** (adapter queries, schema metadata): `snake_case`
  (`device_code`, `wallet_address`, `two_factor`).
- **HTTP JSON** (request/response bodies, OpenAPI): `camelCase` (`userId`,
  `walletAddress`) for Better Auth parity.
- **OAuth protocol endpoints** (device authorization, token grants): RFC-defined
  `snake_case` (`device_code`, `expires_in`) — not converted to camelCase.

Plugin options **metadata** JSON keeps camelCase keys (for example
`schema.walletAddress` on SIWE).

## Operational Notes

- Run adapter migrations after adding plugins that contribute schema.
- Prefer these plugins for server behavior; helper SDKs should stay outside this
  crate.
- API key storage can use the database and selected secondary-storage paths.
- In pure `SecondaryStorage` mode (no database fallback) the `api-key:by-ref:*`
  listing index is mutated through atomic `compare_and_set` /
  `delete_if_value`. Multi-process deployments need a secondary-storage backend
  that implements those methods with real backend atomicity, or the database
  fallback, to keep `/api-key/list` from dropping concurrently written keys.
- OpenAPI support serves generated auth schemas and optional Scalar reference
  UI.

## Status

Experimental beta. Individual plugin APIs, schemas, endpoints, hooks, and
error codes may change before stable release.

## Better Auth compatibility

Server-side official plugin behavior is aligned with Better Auth 1.6.9 where it
matters; RustAuth is not a line-by-line port. For route-level parity, test
counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
