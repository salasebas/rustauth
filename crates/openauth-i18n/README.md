# openauth-i18n

Internationalization plugin for OpenAuth-RS.

## What It Is

`openauth-i18n` localizes OpenAuth JSON error responses. It detects a locale,
looks up the response `code` in your dictionaries, replaces `message`, and
preserves the original message as `originalMessage`.

## What It Provides

- Translation dictionaries keyed by OpenAuth error code.
- Locale detection from `Accept-Language`, cookies, session fields, or sync/async
  resolver callbacks.
- Fallback locale handling.
- A server-side plugin that can be registered with `OpenAuth::builder()`.

## Quick Start

```rust
use openauth::i18n::{i18n, I18nOptions, LocaleDetectionStrategy};
use openauth::OpenAuth;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(i18n(
        I18nOptions::new()
            .locale("en", [("INVALID_EMAIL", "Invalid email")])
            .locale("es", [("INVALID_EMAIL", "Email invalido")])
            .default_locale("en")
            .detection([
                LocaleDetectionStrategy::Cookie,
                LocaleDetectionStrategy::Header,
            ]),
    )?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Notes

- For migrations from an existing `IndexMap` of locale tables, use
  `I18nOptions::from_translations(map)` instead of building dictionaries by hand.
- `Accept-Language` tries exact tags before base tags, for example `pt-BR`
  before `pt`.
- Cookie detection defaults to the `locale` cookie.
- Session detection defaults to a user/session `locale` field.
- Async locale callbacks use `get_locale_async` and require
  `AuthRouter::handle_async` (or the OpenAuth async server path). Sync
  `AuthRouter::handle` keeps synchronous `get_locale` only.

## Status

Experimental beta. Locale detection, translation keys, and plugin behavior may
change before stable release.

## Better Auth compatibility

Server-side i18n plugin that localizes JSON error responses by error `code`.
Aligned with Better Auth **1.6.9** where it matters; OpenAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
