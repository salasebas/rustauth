# Better Auth upstream parity target

Active parity version for RustAuth development:

| Field | Value |
| --- | --- |
| Package | `better-auth` |
| Version | `1.6.9` |
| npm dist-tag checked | `latest` |
| Checked on | `2026-05-09` |
| Source registry | https://registry.npmjs.org/better-auth |
| Repository | https://github.com/better-auth/better-auth |
| Repository tag | `v1.6.9` |
| Repository commit | `f484269228b7eb8df0e2325e7d264bb8d7796311` |

## Local source tree

Clone the monorepo for behavioral reference (not committed to git):

```bash
./scripts/fetch-upstream-better-auth.sh
```

Expected path:

```text
reference/upstream-src/1.6.9/repository/
```

Package sources live under `packages/` (for example `packages/better-auth/`,
`packages/core/`, `packages/sso/`).

## Other versions

`1.7.0-beta.2` existed under the npm `beta` tag when 1.6.9 was pinned, but the
stable `latest` tag pointed to `1.6.9`. To compare against another release,
clone into `reference/upstream-src/<version>/repository/` and update this file
when bumping the workspace parity target.

Do not commit upstream clones. Only this attribution directory is versioned.
