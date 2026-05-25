# openauth-cli

Command-line tools for OpenAuth-RS.

## What It Is

`openauth-cli` provides local developer tooling for OpenAuth projects. The
published package exposes the `openauth` binary and cargo-style aliases.

## What It Provides

- Secret generation.
- Project diagnostics.
- Workspace and package information.
- Schema and migration planning output.
- Project initialization helpers.
- Plugin inspection and changes for official OpenAuth plugins.
- Shell completion generation.

## Quick Start

```sh
openauth secret --bytes 32
openauth doctor --production
openauth schema print --dialect sqlite
openauth plugins list
```

The CLI is intentionally transparent: it inspects the current Rust workspace
and prints or writes OpenAuth configuration/migration output without hiding the
Rust code that owns your application behavior.

## Status

Experimental beta. Commands, flags, generated output, and workspace detection
may change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
