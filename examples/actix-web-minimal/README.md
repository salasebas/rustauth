# rustauth-example-actix-web

Minimal Actix Web server that mounts RustAuth with the in-memory adapter and
test-safe defaults (fast password hashing, relaxed CSRF/origin checks for local
development).

## Run

```bash
cargo run -p rustauth-example-actix-web --manifest-path examples/Cargo.toml
```

Auth API: `http://127.0.0.1:8080/api/auth`

## Test

```bash
cargo nextest run -p rustauth-example-actix-web --manifest-path examples/Cargo.toml
```

## Docs

- [Actix Web integration](https://rustauth.dev/docs/integrations/actix-web)
- Crate README: [`crates/rustauth-actix-web`](../../crates/rustauth-actix-web/README.md)
