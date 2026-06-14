# Security Policy

This project is in experimental beta. Do not use it for production
authentication until the relevant crate is explicitly documented as stable.

This is an independent, unofficial project inspired by Better Auth. It is not
affiliated with, maintained by, endorsed by, or sponsored by the Better Auth
project or its maintainers.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub Security
Advisories for this repository once enabled. Until then, open a minimal public
issue that does not include exploit details and ask for a private disclosure
channel.

## Scope

Security-sensitive behavior should be ported with tests and reviewed against
the pinned upstream Better Auth snapshot in
`reference/upstream-better-auth/VERSION.md` and the local clone at
`reference/upstream-src/<parity-version>/repository/` (see
`./scripts/fetch-upstream-better-auth.sh`).
