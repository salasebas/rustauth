# Outbound delivery security

RustAuth dispatches email and SMS through integrator-provided callbacks. Two
threats matter for password reset, OTP, and verification flows:

1. **Account enumeration** — infer whether an email or phone is registered from
   HTTP status codes or response bodies.
2. **Timing side channels** — infer whether outbound delivery ran from how long
   the server takes to respond (SMTP/SMS latency vs. early exit).

Better Auth documents both concerns for email hooks: return generic success when
the account may not exist, and **do not await** the actual send before returning
the HTTP response (use background delivery such as `waitUntil` on serverless).

RustAuth follows the same model: async sender hooks plus non-blocking dispatch.

## Required integrator pattern

Register real SMTP/SMS work inside an async callback. RustAuth builds the HTTP
response first and runs delivery on a background task.

```rust
use rustauth_plugins::prelude::*;
use std::sync::Arc;

let sender = Arc::new(|payload, _request| {
    Box::pin(async move {
        smtp.send_otp(&payload.email, &payload.otp).await?;
        Ok(())
    })
});

let plugin = email_otp(EmailOtpOptions::new(sender))?;
```

Do **not** block the Tokio worker with synchronous network I/O inside the
handler path. Do **not** `.await` the sender future in application route code
before returning — core and plugins call [`dispatch_outbound`](../crates/rustauth-core/src/outbound.rs) for you.

## Background execution

By default, `AuthContext` uses [`TokioBackgroundTaskRunner`](../crates/rustauth-core/src/background/tokio.rs)
when `AdvancedOptions::background_tasks` is unset. Override with a custom
[`BackgroundTaskRunner`](../crates/rustauth-core/src/options/advanced.rs) for
serverless platforms (map `spawn` to `waitUntil` or your queue).

Delivery failures after the HTTP response are logged at error level; they are not
returned to the client once success was already sent.

## Optional timing padding

`AdvancedOptions::outbound_min_response_time` (default `None`) is available as
configuration for future minimum wall-time padding. Current handlers do not
enforce it yet. Leave unset unless you are testing integration with downstream
padding logic.

## Affected hooks

| Area | Hook / callback | Notes |
|------|-----------------|-------|
| Core | `SendVerificationEmail` | Generic 200 when user missing |
| Core | `SendResetPassword` | Generic 200 when user missing |
| Email OTP | `SendEmailOtp` | Sign-in skips send when `disable_sign_up` and user missing |
| Magic link | `SendMagicLink` | Async; dispatched after verification record |
| Two-factor | `SendOtp` | Async; dispatched after OTP record |
| Phone | `PhoneNumberSender` | Password reset skips DB OTP when user missing |
| Organization | `SendInvitationEmailHook` | Inviter supplies email; dispatched in background |

Verification and password-reset routes preserve anti-enumeration behavior from
Better Auth; this document focuses on non-blocking delivery and timing.

## Migration from sync senders

Sync `Fn(...) -> Result<(), RustAuthError>` senders were removed. Wrap logic in
`Box::pin(async move { ... })` and return `OutboundSendFuture` (re-exported from
`rustauth_core`).

Magic link and two-factor already used async futures; email OTP, core reset/
verify, phone SMS, and organization invitations now match that pattern.
