# openauth-i18n

Internationalization plugin for OpenAuth-RS.

## Status

This package is in experimental beta. Locale detection, translation keys, and
plugin behavior may change before stable release.

## What It Provides

`openauth-i18n` adds localized auth error responses through translation
dictionaries and locale detection strategies. It translates JSON API errors by
looking up the response `code`, replacing `message`, and preserving the original
message in `originalMessage`.

Locale detection supports:

- `Header`: parses `Accept-Language`; exact locale tags such as `pt-BR` are
  tried before base tags such as `pt`.
- `Cookie`: reads a configurable locale cookie. Default: `locale`.
- `Session`: reads a configurable user locale field. Default: `locale`.
- `Callback`: calls a synchronous Rust resolver. Async callback support is not
  exposed yet because plugin response hooks are currently synchronous.

If no detected locale is available, the plugin uses explicit `default_locale`,
then `en` when present, then the first translation locale.

## Example

```rust
use indexmap::IndexMap;
use openauth::{OpenAuth, i18n};

let mut translations = IndexMap::new();
translations.insert(
    "en".to_owned(),
    i18n::translation_dictionary([("INVALID_EMAIL", "Invalid email")]),
);
translations.insert(
    "fr".to_owned(),
    i18n::translation_dictionary([("INVALID_EMAIL", "Email invalide")]),
);

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(i18n::i18n(
        i18n::I18nOptions::new(translations)
            .default_locale("en")
            .detection([
                i18n::LocaleDetectionStrategy::Cookie,
                i18n::LocaleDetectionStrategy::Header,
            ])
            .locale_cookie("lang"),
    )?)
    .build()?;
```

The `openauth::i18n` reexport is available when the `openauth` crate is built
with its `i18n` feature. Applications may also depend on `openauth-i18n`
directly.

Keep application-specific copy in dictionaries and leave authentication logic in
the core and plugin crates.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
