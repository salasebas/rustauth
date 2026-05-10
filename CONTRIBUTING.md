# Contributing

This project is currently an independent, unofficial Python porting workspace
inspired by Better Auth. It is not affiliated with, maintained by, endorsed by,
or sponsored by the Better Auth project or its maintainers.

## Setup

```bash
python -m pip install -e packages/better-auth[dev]
```

## Tests

```bash
python -m pytest packages/*/tests
```

## Package Work

Each package under `packages/` maps to an upstream Better Auth package when
possible. Keep direct porting notes in `PORTING.md`.

When porting behavior:

1. Read the matching upstream package in `upstream/better-auth/packages`.
2. Write a focused Python test.
3. Implement a Python-native equivalent.
4. Keep framework or database specific behavior in a dedicated package.

## Pull Requests

Use conventional commit-style PR titles where possible.
