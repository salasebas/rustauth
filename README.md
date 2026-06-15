# RustAuth

RustAuth is an unofficial Rust authentication toolkit inspired by [Better Auth](https://www.better-auth.com/).
It is server-first: sessions, OAuth/OIDC, SSO, SCIM, SAML, passkeys, plugins, storage adapters,
and Axum integration live in the `rustauth-*` crates.

**0.2.0** is the initial public working release. The API is pre-1.0; breaking changes are still
possible before 1.0.

## Quick start

```rust
use rustauth::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://app.example.com/api/auth")
        .build()
        .await?;

    Ok(())
}
```

Mount into Axum with [`rustauth-axum`](crates/rustauth-axum/README.md):

```rust
use rustauth_axum::RustAuthAxumExt;

let app = auth.mount_at_base_path()?;
```

Run `rustauth init` to create `rustauth.toml`, keep `[plugins].enabled` in sync with the plugins
you register in Rust, then `rustauth db migrate --yes` before serving traffic. See
[docs/database-migrations.md](docs/database-migrations.md).

## Packages

Start with the [umbrella `rustauth` crate](crates/rustauth/README.md) — its README links every
`rustauth-*` package (core, axum, cli, plugins, OAuth, SSO, SCIM, adapters, and more).

### Database adapters

SQLx (`rustauth-sqlx`) is the primary adapter family for SQLite, Postgres, and MySQL.
For apps that already use Diesel, [`rustauth-diesel`](crates/rustauth-diesel/README.md)
provides Postgres and MySQL adapters via `diesel-async`. Native Postgres pools are
also available through `rustauth-tokio-postgres` and `rustauth-deadpool-postgres`.

## Docs and parity

- Site: [rustauth.dev](https://rustauth.dev)
- Better Auth parity index: [`docs/parity/README.md`](docs/parity/README.md)
- Upstream pin: [`reference/upstream-better-auth/VERSION.md`](reference/upstream-better-auth/VERSION.md)

## Repository

Source: [salasebas/rustauth](https://github.com/salasebas/rustauth)

## Testing

```bash
cargo install --locked cargo-nextest
./scripts/ensure-test-services.sh postgres mysql redis valkey
cargo nextest run --workspace --all-features
cargo test --workspace --doc --all-features
```

## License

MIT — see [LICENSE](LICENSE).
