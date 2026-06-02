# 07 — Tests and coverage

## Counts

| Suite | Files | Tests | Runner |
| --- | --- | --- | --- |
| **Upstream** | `src/telemetry.test.ts` | **6** | Vitest |
| **OpenAuth unit** | `src/env.rs`, `src/detectors/*.rs` | **13** | `#[test]` |
| **OpenAuth integration** | `tests/telemetry.rs` | **21** (19 async + 2 sync; +1 oauth-only) | `#[tokio::test]` / `#[test]` |
| **OpenAuth total (default)** | — | **33** | `cargo test -p openauth-telemetry` |
| **OpenAuth + oauth** | — | **34** | `--features oauth` (+1 social snapshot test) |

| Metric | Value |
| --- | --- |
| Approximate ratio | **5.5×** more Rust tests than upstream Vitest |
| Upstream coverage | All **6** cases have an explicit or stronger equivalent |

## Matrix: upstream Vitest → Rust

| # | Upstream `it(...)` | OpenAuth equivalent | Extra |
| --- | --- | --- | --- |
| 1 | `publishes events when enabled` | `publishes_init_when_enabled` + `auth_config_snapshot_reports_modeled_options_with_upstream_keys` | Config JSON superset |
| 2 | `does not publish when disabled via env` | `does_not_publish_when_disabled_via_env` | — |
| 3 | `does not publish when disabled via option` | `does_not_publish_when_disabled_via_option` | — |
| 4 | `shouldn't fail cause track isn't being reached` | `panicking_custom_track_does_not_abort_create_telemetry` | — |
| 5 | `initializes without Node built-ins in edge-like env` | `init_with_missing_manifest_env_still_tracks` | Simulates missing `CARGO_MANIFEST_DIR` |
| 6 | `returns noop publisher when ENDPOINT undefined` | `noop_skips_http_transport_when_no_endpoint_and_no_custom_sink` + `empty_endpoint_env_is_treated_as_missing_endpoint` | HTTP mock transport |

## Rust tests without upstream equivalent (by category)

### Enablement / env

| Test | Validates |
| --- | --- |
| `telemetry_env_true_enables_init_publish` | `OPENAUTH_TELEMETRY=true` |
| `telemetry_env_one_enables_init_publish` | `OPENAUTH_TELEMETRY=1` |
| `telemetry_env_zero_does_not_enable_init_publish` | `=0` does not enable via env alone |
| `env_opt_out_overrides_options_enabled` | **OpenAuth decision** |
| `env_opt_in_overrides_options_disabled` | env forces on |
| `test_environment_suppresses_telemetry_without_skip_test_check` | `RUST_ENV=test` |

### Transport / debug

| Test | Validates |
| --- | --- |
| `endpoint_env_posts_init_to_configured_collector` | mock POST |
| `custom_track_wins_over_configured_endpoint` | sink priority |
| `debug_mode_skips_http_posting` | option debug |
| `debug_env_skips_http_posting` | env debug |
| `publish_reuses_resolved_anonymous_id_and_overrides_caller_id` | later publish |
| `slow_init_custom_track_does_not_block_create_telemetry` | async spawn |

### OAuth / config (feature)

| Test | Validates |
| --- | --- |
| `auth_config_snapshot_reports_social_provider_options_without_credentials` | no client id/secret |

### CLI shape

| Test | Validates |
| --- | --- |
| (in `publish_reuses_...` or cli_generate block) | preserves `cli_generate` event type |

## Unit tests by module

| Module | Tests | Focus |
| --- | --- | --- |
| `env.rs` | 3 | `RUST_ENV`, `is_test` |
| `detectors/database.rs` | 2 | inline + workspace manifest |
| `detectors/framework.rs` | 2 | axum present / absent |
| `detectors/package_manager.rs` | 3 | cargo env |
| `detectors/system_info.rs` | 3 | host, vendor |

## Coverage gaps (neither upstream nor OpenAuth today)

| Area | Upstream | OpenAuth | Priority |
| --- | --- | --- | --- |
| Exhaustive empty snapshot | no | partial via superset test | medium |
| Stable / random project ID | no | no | medium |
| Every deployment vendor env | no | 1 mock (vercel) | low |
| HTTP error logging | no | no | low |
| `databaseHooks` when core models them | no | no | high (after core) |

## Related tests outside this crate

| Test | Crate | Notes |
| --- | --- | --- |
| `openauth_async_builder_wires_context_telemetry_publisher` | `openauth` | feature wiring E2E |
| stderr `cli_generate` | `openauth-cli` | CLI telemetry smoke |

## Regression commands

```bash
cargo fmt --all --check
cargo clippy -p openauth-telemetry --all-targets -- -D warnings
cargo nextest run -p openauth-telemetry
cargo nextest run -p openauth-telemetry --features oauth
```

## Out of scope for this crate’s tests

| Topic | Owner |
| --- | --- |
| External collector retention policy | Operator infra |
| OpenTelemetry spans | future instrumentation crate |
| Client UI | N/A server-only |
