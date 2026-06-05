# openauth-i18n

Internationalization plugin for OpenAuth-RS.

## What It Is

`openauth-i18n` localizes OpenAuth JSON error responses. It detects a locale,
looks up the response `code` in your dictionaries, replaces `message`, and
preserves the original message as `originalMessage`.

## What It Provides

- Translation dictionaries keyed by OpenAuth error code.
- Locale detection from `Accept-Language`, cookies, session fields, or a
  synchronous resolver callback.
- Fallback locale handling.
- A server-side plugin that can be registered with `OpenAuth::builder()`.

## Quick Start

```rust
use indexmap::IndexMap;
use openauth::OpenAuth;
use openauth_i18n::{
    i18n, translation_dictionary, I18nOptions, LocaleDetectionStrategy,
};

let mut translations = IndexMap::new();
translations.insert(
    "en".to_owned(),
    translation_dictionary([("INVALID_EMAIL", "Invalid email")]),
);
translations.insert(
    "es".to_owned(),
    translation_dictionary([("INVALID_EMAIL", "Email invalido")]),
);

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(i18n(
        I18nOptions::new(translations)
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

- `Accept-Language` tries exact tags before base tags, for example `pt-BR`
  before `pt`.
- Cookie detection defaults to the `locale` cookie.
- Session detection defaults to a user/session `locale` field.
- Async locale callbacks are not exposed yet because response hooks are
  currently synchronous.

## Status

Experimental beta. Locale detection, translation keys, and plugin behavior may
change before stable release.

## Upstream parity (Better Auth 1.6.9)

Parity pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
Upstream package: `@better-auth/i18n` (server plugin only; `@better-auth/i18n/client` is
N/A for this server-only crate). Re-exported from `openauth` with feature `i18n`.

| Area | Server parity | Notes |
| --- | --- | --- |
| API error translation (`code` → `message`, `originalMessage`) | High | Same JSON shape as upstream |
| Locale detection (`header`, `cookie`, `session`, `callback`) | High | Same strategy order |
| `Accept-Language` parsing | High | Case-insensitive; exact region before base tag |
| Router early exits + rate limit / 404 / `INVALID_ORIGIN` | High | `finalize_response` applies `on_response` |
| Session locale hydration | High | Async user lookup with `user_output_value` |
| `getLocale` async | Partial | Response hooks are synchronous in Rust today |
| `i18nClient` | N/A | Client-only TypeScript |
| Package tests | Superset | 15 upstream Vitest → 64 Rust tests |

Verify: `cargo nextest run -p openauth-i18n`.

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Server plugin: `reference/upstream-src/<version>/repository/packages/i18n/src/` (ignore `client/`).
3. Map `crates/openauth-i18n/src/` to upstream plugin hooks and `*.test.ts`.
4. Verify: `cargo nextest run -p openauth-i18n`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
