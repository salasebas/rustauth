# Release Process

This release process is for the independent, unofficial `better-auth-py`
package family. These distributions are not affiliated with, maintained by,
endorsed by, or sponsored by the Better Auth project or its maintainers.

This repository does not copy Better Auth's Changesets setup because that flow
is built around pnpm and npm package publishing.

The Python port uses GitHub releases and PyPI Trusted Publishing instead:

1. Update package versions in each changed `packages/*/pyproject.toml` and
   `packages/better-auth/src/better_auth/_version.py`.
2. Create a GitHub release.
3. The `Publish Python package` workflow builds all package distributions into
   root `dist/`.
4. `pypa/gh-action-pypi-publish` publishes the distributions with OIDC.

`release-preview.yml` can be run manually, or by labeling a pull request with
`release-preview`, to verify package builds before publishing.

## Package Names

PyPI package names are part of each built distribution's metadata. This port
publishes only the canonical `better-auth*` distributions.

- Main distribution: `better-auth-py`
- Extension packages: `better-auth-stripe`, `better-auth-sso`,
  `better-auth-api-key`, etc.
