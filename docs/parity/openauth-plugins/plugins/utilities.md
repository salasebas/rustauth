# Utility plugins: access, bearer, captcha, additional-fields

Plugins without HTTP routes or with an auxiliary role. Complements [06-plugin-master-map.md](../06-plugin-master-map.md).

---

## access

| Field | Value |
|-------|-------|
| Status | ✅ Full |
| Endpoints | — |
| Schema | — |
| Hooks | — |
| API | `create_access_control`, `role`, `request`, `authorize`, `AccessControl`, `Role` |
| Consumers | admin, organization |
| Tests | 24 OA / 6 UP |

---

## additional-fields

| Field | Value |
|-------|-------|
| Status | 🎯 Intentional |
| Endpoints | — |
| Schema | `PluginSchemaContribution::field` user/session |
| Hooks | `init` |
| Upstream | Client-only TS; OA server schema |
| Options | `AdditionalFieldsOptions`, `AdditionalField` (type, required, unique, index, db_name, …) |
| Tests | 3 OA / 10 UP |

---

## bearer

| Field | Value |
|-------|-------|
| Status | ✅ Full |
| Endpoints | — |
| Hooks | `on_request`, `on_response` |
| Options | `BearerOptions.require_signature` |
| Semantics | Token with `.` → verify; no `.` + require → ignore; no `.` + !require → sign & inject |
| Tests | 16 OA / 5 UP |

---

## captcha

| Field | Value |
|-------|-------|
| Status | ✅ Full |
| Endpoints | — |
| Hooks | `async_middleware *` |
| Providers | cloudflare-turnstile, google-recaptcha, h-captcha, captchafox |
| Header | `x-captcha-response` |
| Options | `CaptchaOptions` (provider, secret, endpoints, min_score, site_key) |
| Tests | 19 OA / 17 UP |

---

## haveibeenpwned

See [hooks-and-utilities.md](./hooks-and-utilities.md#haveibeenpwned).

---

## last-login-method

See [hooks-and-utilities.md](./hooks-and-utilities.md#last-login-method).

---

## custom-session

See [hooks-and-utilities.md](./hooks-and-utilities.md#custom-session).

---

## open-api

See [hooks-and-utilities.md](./hooks-and-utilities.md#open-api).
