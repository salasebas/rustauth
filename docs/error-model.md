# Error model

RustAuth uses layered error types. Each layer has a distinct job; phase 1 (plan
009) documents the layers and adds conversion bridges without merging enums.

**Parity reference**: Better Auth separates API error codes, auth-flow failures,
and plugin-contributed codes. RustAuth mirrors that shape in Rust.

## Layers

```text
Domain / service          HTTP wire                 Plugin registry
─────────────────         ─────────                 ───────────────
RustAuthError      →      ApiErrorResponse          PluginErrorCode
AuthFlowError      →      (via to_api_response)     (validate + register)
OAuthUserInfoError →      redirect / error URL      —
rustauth_oauth::OAuthError → RustAuthError::OAuth   —
```

### 1. Core library (`RustAuthError`)

**Location**: `crates/rustauth-core/src/error.rs`

Catch-all for configuration, serialization, crypto, adapter, and wrapped
protocol errors. Integrators and internal code use `Result<_, RustAuthError>`
at crate boundaries.

| Variant family | Typical source |
| --- | --- |
| `InvalidConfig`, `InvalidSecretConfig` | Options validation at startup |
| `Serialization`, `Cookie`, `Crypto` | Request/response building |
| `Adapter`, `PasswordHash` | Storage and credential operations |
| `OAuth(String)` | OAuth protocol and user-info linking failures |
| `Api(String)` | Stable API code strings from `error_codes` |

**Bridges (phase 1)**:

- `rustauth_oauth::oauth2::OAuthError` → `RustAuthError::OAuth` (feature `oauth`)
- `OAuthUserInfoError` → `RustAuthError::OAuth` (account-linking domain)

### 2. Auth flows (`AuthFlowError` / `AuthFlowErrorCode`)

**Location**: `crates/rustauth-core/src/auth/email_password.rs`

Email/password sign-up and sign-in outcomes. Codes align with Better Auth
`BASE_ERROR_CODES` where applicable (`error_codes.rs`).

| Method | Role |
| --- | --- |
| `AuthFlowError::http_status()` | Maps flow code → HTTP status |
| `AuthFlowError::to_api_response()` | Maps flow error → `ApiErrorResponse` |

HTTP routes call `auth_flow_error_response` in `api/routes/shared.rs`, which
delegates to these methods. **Do not change** the JSON shape (`code`, `message`,
optional `originalMessage`) without a semver-major release.

Status mapping (stable):

| Code | HTTP status |
| --- | --- |
| `INVALID_EMAIL_OR_PASSWORD` | 401 Unauthorized |
| `EMAIL_NOT_VERIFIED` | 403 Forbidden |
| `STORAGE_ERROR`, `FAILED_TO_CREATE_SESSION` | 500 Internal Server Error |
| `INVALID_EMAIL`, `INVALID_PASSWORD_LENGTH`, `USER_ALREADY_EXISTS`, `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | 400 Bad Request |

### 3. HTTP API envelope (`ApiErrorCode` / `ApiErrorResponse`)

**Location**: `crates/rustauth-core/src/api/error.rs`

Framework-level errors: trusted origins, callback URLs, rate limits, not found.
Produced by `api_error()` and route helpers. Wire format uses upper snake_case
`code` strings and camelCase `originalMessage` when set (see
[http-json-conventions.md](http-json-conventions.md)).

### 4. OAuth user-info linking (`OAuthUserInfoError`)

**Location**: `crates/rustauth-core/src/auth/oauth/errors.rs`

Social/OAuth account linking outcomes (not linked, signup disabled, storage
failures). HTTP social routes surface `code_str()` as the user-visible message
on redirect/error URLs; `From<OAuthUserInfoError> for RustAuthError` bridges
into the core error type for `?` propagation.

| Variant | `code_str()` |
| --- | --- |
| `AccountNotLinked` | `account_not_linked` |
| `SignupDisabled` | `signup_disabled` |
| `UnableToCreateUser` | `unable_to_create_user` |
| `UnableToCreateSession` | `unable_to_create_session` |
| `UnableToLinkAccount` | `unable_to_link_account` |

### 5. Plugin error registry (`PluginErrorCode`)

**Location**: `crates/rustauth-core/src/plugin/error.rs`

Plugins register additional upper snake_case codes at init. Validation rejects
empty or non–upper-snake codes. Plugin-specific option errors (e.g.
`CaptchaConfigError`) remain separate; see follow-up below.

## Shared `ErrorCode` trait

**Location**: `crates/rustauth-core/src/error_codes.rs`

Core error-code enums and plugin registry entries implement a shared trait for
stable wire metadata:

| Method | Role |
| --- | --- |
| `as_str()` | Upper snake_case code string |
| `message()` | Default English message |

Implementors:

| Type | Location |
| --- | --- |
| `ApiErrorCode` | `crates/rustauth-core/src/api/error.rs` |
| `AuthFlowErrorCode` | `crates/rustauth-core/src/auth/email_password.rs` |
| `PluginErrorCode` | `crates/rustauth-core/src/plugin/error.rs` |
| `StripeErrorCode` | `crates/rustauth-stripe/src/errors.rs` |
| `CaptchaErrorCode` | `crates/rustauth-plugins/src/captcha/error.rs` |
| `AnonymousError` | `crates/rustauth-plugins/src/anonymous/errors.rs` |

`ApiErrorResponse::from_error_code` builds the HTTP JSON envelope from any
`impl ErrorCode`. Downstream plugins may implement `ErrorCode` directly for
their own error-code types. The i18n plugin uses a sealed blanket
`TranslationKey` impl for core `ErrorCode` types (`ApiErrorCode`,
`AuthFlowErrorCode`, `PluginErrorCode`); external `ErrorCode` implementors
still work with `translation_dictionary` via string keys or by adding their own
`TranslationKey` impl.

Inherent `as_str()` / `message()` methods on the enums are unchanged; the trait
delegates to them (or to `PluginErrorCode`'s `code` / `message` fields).

Plugin error-code coverage:

| Type | Trait test |
| --- | --- |
| `StripeErrorCode` | `SubscriptionNotFound` → `SUBSCRIPTION_NOT_FOUND` |
| `CaptchaErrorCode` | `VerificationFailed` → `VERIFICATION_FAILED` |
| `AnonymousError` | `InvalidEmailFormat` → `INVALID_EMAIL_FORMAT` |

`AnonymousError::error_response` uses `ApiErrorResponse::from_error_code` for the
same wire shape as the previous manual struct.

## Related

- `crates/rustauth-core/src/error_codes.rs` — stable string constants
- Plan 009 — phase 1 bridges and this document
- Plan 010 / 017 — HTTP JSON camelCase (orthogonal to error code strings)
