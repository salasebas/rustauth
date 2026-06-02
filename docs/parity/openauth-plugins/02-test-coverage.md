# Test coverage: `openauth-plugins` vs upstream

Counts over v1.6.9 source trees and `crates/openauth-plugins/tests/`.

**OpenAuth methodology:** `#[test]` + `#[tokio::test]` per `tests/<plugin>/` directory.  
**Upstream methodology (preferred):** `it(` only in `*.test.ts` — excludes `describe(` blocks that inflated ratios.

> See also [04-deep-audit-findings.md](./04-deep-audit-findings.md) for concrete scenarios by test name.

---

## Global summary

| Metric | OpenAuth | Upstream (server) |
|---------|----------|-------------------|
| Total tests | **610** | **986** `it()` |
| With `describe` included | — | ~1202 |
| Approximate ratio | 1x | **1.6x** |
| Plugins with more OA tests | access, bearer, haveibeenpwned, multi_session, siwe, **one_tap (14 vs 0)** | — |
| Largest `it()` gap | organization (−150), api-key (−124), email-otp (−42), two-factor (−34) | — |

Excluded: `test-utils` (19), `oidc-provider` (32).

---

## Per-plugin table (`it()` upstream)

| Plugin | OpenAuth | Upstream `it()` | Δ | Ratio | Notes |
|--------|:--------:|:---------------:|:-:|:-----:|-------|
| access | 24 | 6 | +18 | 4.0x | |
| additional_fields | 3 | 10 | −7 | 0.3x | upstream client types |
| admin | 29 | 71 | −42 | 0.41x | OA covers list-users filters in `parity.rs` |
| anonymous | 18 | 12 | +6 | 1.5x | |
| api_key | 52 | 176 | −124 | 0.30x | |
| bearer | 16 | 5 | +11 | 3.2x | |
| captcha | 19 | 17 | +2 | 1.1x | |
| custom_session | 18 | 11 | +7 | 1.6x | |
| device_authorization | 36 | 31 | +5 | 1.2x | |
| email_otp | 31 | 73 | −42 | 0.42x | |
| generic_oauth | 41 | 59 | −18 | 0.69x | 29 tests in `routes.rs` |
| haveibeenpwned | 12 | 4 | +8 | 3.0x | |
| jwt | 33 | 36 | −3 | 0.92x | |
| last_login_method | 20 | 21 | −1 | 0.95x | |
| magic_link | 27 | 18 | +9 | 1.5x | + `upstream_parity.rs` |
| mcp | 30 | 36 | −6 | 0.83x | upstream incl. client adapter tests |
| multi_session | 22 | 9 | +13 | 2.4x | |
| oauth_proxy | 24 | 18 | +6 | 1.3x | |
| one_tap | 14 | **0** | +14 | ∞ | **no upstream tests** |
| one_time_token | 15 | 13 | +2 | 1.2x | |
| open_api | 9 | 9 | 0 | 1.0x | incl. audit 80+ endpoints |
| organization | 32 | **182** | −150 | 0.18x | check-slug + limits tests added Jun 2026 |
| phone_number | 22 | 32 | −10 | 0.69x | |
| siwe | 25 | 17 | +8 | 1.5x | |
| two_factor | 21 | 55 | −34 | 0.38x | incl. view-backup-codes, generate-totp |
| username | 12 | 33 | −21 | 0.36x | |
| integration_matrix | 3 | — | — | — | 7 plugins, `#[ignore]` |
| plugins.rs | 2 | — | — | — | plugin ID inventory |

---

## Cross-cutting OpenAuth tests (not per plugin)

| Test | What it validates |
|------|-------------------|
| `plugins.rs::plugin_ids_expose_supported_server_plugins` | 27 IDs == `PLUGIN_IDS` |
| `plugins.rs::upstream_server_plugin_parity_is_explicit_about_replaced_oidc_provider` | oidc → oauth-provider |
| `open_api::generated_schema_audits_all_server_plugin_endpoints` | >80 paths, operationId, tags, body schemas |
| `integration_matrix::*` | E2E Docker: admin, org, api_key, jwt, ott, multi_session, 2FA |

---

## Commands to regenerate counts

```bash
# OpenAuth
python3 - <<'PY'
import re, glob, os
from collections import defaultdict
base = "crates/openauth-plugins/tests"
counts = defaultdict(int)
for path in glob.glob(base + "/**/*.rs", recursive=True):
    plugin = os.path.relpath(path, base).split(os.sep)[0]
    with open(path) as f:
        counts[plugin] += len(re.findall(r'#\[(?:tokio::)?test\]', f.read()))
for k in sorted(counts): print(f"{k}: {counts[k]}")
print("TOTAL:", sum(counts.values()))
PY

# Upstream — it() only
python3 - <<'PY'
import re, glob, os
from collections import defaultdict
def count(base):
    c=defaultdict(int)
    for f in glob.glob(base+'/**/*.test.ts', recursive=True):
        mod=os.path.relpath(f,base).split(os.sep)[0]
        c[mod]+=len(re.findall(r'\bit\s*\(', open(f).read()))
    return c
up=count("reference/upstream-src/1.6.9/repository/packages/better-auth/src/plugins")
ak=count("reference/upstream-src/1.6.9/repository/packages/api-key/src")
up['api-key']=sum(ak.values())
for k in sorted(up):
    if k!='test-utils': print(f"{k}: {up[k]}")
print("TOTAL:", sum(v for k,v in up.items() if k not in ('test-utils',)))
PY
```
