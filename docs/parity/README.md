# Upstream parity documentation

Structured parity notes for OpenAuth crates against Better Auth **v1.6.9**
([`reference/upstream-better-auth/VERSION.md`](../reference/upstream-better-auth/VERSION.md)).

Each subdirectory documents one Rust crate (or logical surface): upstream mapping,
behavior, tests, and intentional design differences.

| Crate / surface | Upstream reference | Status |
| --- | --- | --- |
| [`openauth-stripe`](openauth-stripe/README.md) | `@better-auth/stripe` | High server parity; **174** Rust integration tests vs upstream Vitest catalog; gaps G1–G12 closed |
| [`openauth-telemetry`](openauth-telemetry/README.md) | `@better-auth/telemetry` | High server parity; **6** upstream Vitest vs **33** Rust tests (**34** with `oauth`); see [gaps](openauth-telemetry/09-gaps-and-follow-ups.md) |

Additional crate parity folders may exist as work-in-progress under `docs/parity/`; the table above lists documented surfaces committed with this index.

Fetch upstream sources locally:

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected tree: `reference/upstream-src/1.6.9/repository/`.
