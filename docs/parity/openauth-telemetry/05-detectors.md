# 05 — Detectors

Common shape upstream and OpenAuth: `DetectionInfo { name, version }` or `null` / `None`.

## Runtime

| | Upstream `detectRuntime` | OpenAuth `detect_runtime` |
| --- | --- | --- |
| Values | `deno`, `bun`, `node`, `edge` | **`rust`** |
| Version | JS runtime version | `RUSTC_VERSION` env |
| Browser | no | no |

**Classification:** **Rust decision** — do not pretend to be Node/Bun.

## Environment (`detectEnvironment`)

| Order | Upstream | OpenAuth |
| --- | --- | --- |
| 1 | `NODE_ENV === production` | `RUST_ENV == production` |
| 2 | `isCI()` | `is_ci()` (same vars; `CI=false` excluded) |
| 3 | `isTest()` | `is_test()` (`RUST_ENV=test` or `TEST`) |
| 4 | fallback | `development` |

**Intent parity:** yes.

## Database

### Upstream (`detect-database.ts`)

Scans `package.json` / `node_modules` versions for:

| npm package | Normalized name |
| --- | --- |
| `pg` | postgresql |
| `mysql` | mysql |
| `mariadb` | mariadb |
| `sqlite3`, `better-sqlite3` | sqlite |
| `@prisma/client` | prisma |
| `mongoose`, `mongodb` | mongodb |
| `drizzle-orm` | drizzle |

### OpenAuth (`database.rs` + `cargo_manifest.rs`)

First match in host `[dependencies]`:

| Crate | Reported name |
| --- | --- |
| `sqlx` | sqlx |
| `diesel` | diesel |
| `sea-orm` | sea-orm |
| `tokio-postgres`, `postgres`, … | postgresql |
| `mysql`, `mysql_async` | mysql |
| `rusqlite`, `sqlite` | sqlite |
| `mongodb` | mongodb |
| `surrealdb` | surrealdb |

| Topic | Status |
| --- | --- |
| prisma / drizzle / mariadb via npm | **N/A** on pure Rust server |
| Override `context.database` | CLI sets it; manifest detector is fallback |
| Unit tests | 2 (inline + workspace deps) |

## Framework

### Upstream

next, nuxt, react-router, astro, sveltekit, solid-start, tanstack-start, hono, express, elysia, expo.

### OpenAuth

axum, actix-web, rocket, poem, warp, tide, salvo, hono (Rust crate).

| Topic | Status |
| --- | --- |
| JS meta-frameworks (Next, Nuxt, …) | **N/A** unless hybrid app exposes metadata — we do not scan JS `package.json` |
| hono | Name collision; upstream = JS package, OpenAuth = Rust crate |
| Tests | 2 manifest unit tests |

## Package manager

| | Upstream `detectPackageManager` | OpenAuth `detect_package_manager` |
| --- | --- | --- |
| Source | `npm_config_user_agent` | `CARGO_MANIFEST_DIR` / cwd + `Cargo.toml` |
| Name | npm, pnpm, yarn, cnpm, … | **`cargo`** |
| Version | parse user-agent | `CARGO_VERSION` |
| **Classification** | JS-only | **Rust decision** |

Tests: 3 unit tests.

## System info

### Upstream

- **Edge build** (`detect-system-info.ts`): mostly `null`.
- **Node build** (`node.ts`): `os` cpus, memory, Docker, WSL, TTY, `getVendor()`.

### OpenAuth (`system_info.rs`)

| Field | OpenAuth | Upstream Node | Notes |
| --- | --- | --- | --- |
| `deploymentVendor` | env vars (cloudflare, vercel, …) | same | Parity |
| `systemPlatform` | `std::env::consts::OS` | `os.platform()` | Parity |
| `systemRelease` | `/proc/sys/kernel/osrelease` or null | `os.release()` | Partial on macOS/Windows |
| `systemArchitecture` | `consts::ARCH` | `os.arch()` | Parity |
| `cpuCount` | `available_parallelism` | `cpus.length` | Parity |
| `cpuModel` | **null** | string | **Decision** (no sysinfo dep) |
| `cpuSpeed` | **null** | MHz | **Decision** |
| `memory` | **null** | `totalmem` | **Decision** |
| `isDocker` | `/.dockerenv`, cgroup, containerenv | same + cache | Parity |
| `isWSL` | `/proc` heuristics | same | Parity |
| `isTTY` | `stdout.is_terminal()` | `process.stdout.isTTY` | Parity |
| `isCI` | `env::is_ci()` | `isCI()` | Parity |

Tests: 3 unit tests (host fields, vendor none, mocked vercel).

## Project ID

| Step | Upstream `getProjectId` | OpenAuth `resolve_project_id` |
| --- | --- | --- |
| Cache | global module cache | per `TelemetryPublisher` + init |
| 1 | hash(`package.json`.name) ± baseUrl | hash(`Cargo.toml` name) ± baseUrl |
| 2 | hash(baseUrl) | hash(baseUrl) |
| 3 | `generateId(32)` | same |
| Algorithm | SHA-256 base64 | SHA-256 base64 (`sha2` + `base64`) |

**Algorithm parity:** yes. **Project name source:** npm vs Cargo — **Rust decision**.

Dedicated project-id tests: **none yet** (documented gap).

## Utilities

| Util | Upstream | OpenAuth |
| --- | --- | --- |
| `hashToBase64` | `@better-auth/utils` | `utils/hash.rs` |
| `generateId` | utils random | `utils/id.rs` (alphanumeric) |
| `package-json` helpers | Node FS | `cargo_manifest.rs` |
