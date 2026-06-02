# Parity: jwt

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/jwt/` |
| OpenAuth | `crates/openauth-plugins/src/jwt/` |
| Plugin ID | `jwt` |
| Tests | **33** OA / **49** BA |
| Global status | 🎯 **Intentional** — full functionality; sign/verify as explicit HTTP |

---

## Endpoints / capabilities

| Capability | Upstream | OpenAuth | Status |
|-----------|----------|----------|--------|
| JWKS | `GET {jwksPath}` default `/jwks` | ✅ | ✅ |
| Session JWT | `GET /token` | ✅ | ✅ |
| Sign JWT | Path-less server API (`auth.api.signJWT`) | `POST /sign-jwt` | 🎯 Intentional |
| Verify JWT | Path-less server API (`auth.api.verifyJWT`) | `POST /verify-jwt` | 🎯 Intentional |
| Header on get-session | `set-auth-jwt` via after hook | ✅ | ✅ |

---

## Schema

| Table | OA | BA |
|-------|:--:|:--:|
| `jwks` | ✅ | ✅ |
| Rotation fields | ✅ | ✅ |
| Grace period filtering | ✅ | ✅ |
| Schema rename options | ✅ | ✅ Jun 2026 |

---

## Hooks

| Hook | OA | BA |
|------|:--:|:--:|
| After `/get-session` → JWT header | ✅ | ✅ |
| `disableSettingJwtHeader` opt-out | ✅ | ✅ |

---

## Options

| Option | OA | BA |
|--------|:--:|:--:|
| `jwks.remoteUrl` | ✅ | ✅ |
| `jwksPath` configurable | ✅ | ✅ |
| `keyPairConfig` (alg, extractable) | ✅ | ✅ |
| Rotation + grace period | ✅ | ✅ |
| `jwt.issuer`, `jwt.audience` | ✅ | ✅ |
| `jwt.expirationTime` | ✅ | ✅ |
| Custom `sign`, `definePayload`, `getSubject` | ✅ | ✅ |

---

## OpenAuth tests

| File | Tests | Focus |
|---------|-------|---------|
| `mod.rs` | 13 | plugin + integration |
| `endpoints.rs` | 9 | /token, /jwks |
| `crypto_adapter.rs` | 6 | crypto layer |
| `sign_verify.rs` | 4 | sign/verify JWT |
| `claims.rs` | 1 | payload claims |

Upstream additional: `rotation.test.ts` (3 blocks) — key rotation.

---

## Upstream scenarios not covered

1. Concurrent rotation — sign during grace period under load
2. Remote JWKS fetch disabled/enabled matrix
3. Exhaustive algorithm validation
4. Remote URL strategy edge cases

---

## Intentional differences

| Topic | Upstream | OpenAuth |
|------|----------|----------|
| Sign/verify surface | Server-only API without HTTP path | Explicit POST routes |
| Crypto | Web Crypto / jose | Rust crypto stack (`jwt/crypto.rs`) |
| Errors | APIError | Result + typed HTTP status |

Exposing `/sign-jwt` and `/verify-jwt` may be **broader** than upstream if published without restriction — consider auth middleware in deployments.
