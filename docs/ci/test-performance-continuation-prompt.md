# Continuation Prompt

Paste this into a fresh session to continue CI/test performance work.

```text
We are in /Users/sebastiansala/projects/openauth.

Goal: keep fast CI + Integration/e2e coverage without regressing timings.

Read first:
- AGENTS.md
- docs/ci/test-performance-roadmap.md
- docs/ci/integration-e2e-workflow.md
- .github/workflows/ci.yml
- .github/workflows/integration.yml

Current state (2026-06-08, push 6f26ea0b):
- Two workflows: CI (fast, no Docker) and Integration (Docker + ignored tests + e2e).
- Fast CI run 27171088989: success, ~173s wall (was ~19m monolithic).
  - openauth-plugins nextest: 733 passed, 3 skipped in 5.7s (job wall 108s).
  - openauth-core nextest: 594 passed in 34.4s (job wall 94s).
- Integration run 27171088982: scim MySQL race failed; fix committed with MYSQL_ADAPTER_TEST_LOCK.
- Helpers: openauth_core::test_utils::{with_integration_test_defaults, fast_hash_password, fast_verify_password}.
- docs/ci/ tracks roadmap + integration/e2e doc (not necessarily committed unless user asks).

Rules:
- Respect AGENTS.md (scoped fmt/clippy/nextest per crate).
- Fast password callbacks are test fixtures only; real scrypt stays in openauth-core crypto tests.
- Do not commit docs/ci/ unless the user asks to update/commit docs.

Verify after changes:
  cargo fmt --all --check
  cargo clippy -p <crate> --all-targets -- -D warnings
  cargo nextest run -p <crate> --all-features

Audit CI:
  gh run list --workflow CI --limit 5
  gh run list --workflow Integration --limit 5
  gh run view <RUN_ID> --json jobs --jq '.jobs[] | [.name, .conclusion] | @tsv'
```
