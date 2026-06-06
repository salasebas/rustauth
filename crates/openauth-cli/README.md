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

These commands work in any directory and do not need an `openauth.toml`:

```sh
openauth secret --bytes 32              # generate a signing secret
openauth plugins list                   # list official plugins
openauth schema print --dialect sqlite  # print the base OpenAuth schema
openauth doctor                         # diagnose the environment
```

Without a config, `doctor` reports what is missing (including the absent
`openauth.toml`) and `schema print` emits the default schema, so the CLI is
useful before any project setup.

To create a project and unlock the config-bound workflow, run `openauth init`
first. It writes `openauth.toml`, syncs `.env.example`, and creates or updates
`.env` in the current directory. Missing keys are merged in without overwriting
values that are already present; a new `.env` is copied from `.env.example` and
uses placeholder secrets unless you pass `--seed-secrets` to generate a signing
secret for local development. The following commands read `openauth.toml`:

```sh
openauth init                # openauth.toml + .env.example + .env
openauth init --seed-secrets # same, but a new .env gets a generated OPENAUTH_SECRET
openauth doctor --production # config-aware production readiness checks
openauth db generate         # generate a migration from the configured schema
openauth db migrate          # apply pending migrations
```

The CLI is intentionally transparent: it inspects the current Rust workspace
and prints or writes OpenAuth configuration/migration output without hiding the
Rust code that owns your application behavior.

## Environment variables

Before running config-backed commands, the CLI loads `.env` and `.env.local`
without overriding variables already set in the process environment. When
`--config` points at a file outside the project root layout, files next to that
config are loaded first, then files in `--cwd` (weaker to stronger:
`config/.env`, `config/.env.local`, `<cwd>/.env`, `<cwd>/.env.local`).

## Status

Experimental beta. Commands, flags, generated output, and workspace detection
may change before stable release.

## Better Auth compatibility

Developer CLI and local schema/migration tooling aligned with Better Auth
**1.6.9** where it matters; OpenAuth is not a line-by-line port.

For command-level parity, test counts, intentional differences, and known gaps,
see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
