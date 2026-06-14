# Local Better Auth upstream clone

This directory holds shallow git clones for parity work. Contents are
**gitignored** and are not published with RustAuth crates.

1. Read the active pin in [`../upstream-better-auth/VERSION.md`](../upstream-better-auth/VERSION.md).
2. From the repository root, run:

   ```bash
   ./scripts/fetch-upstream-better-auth.sh
   ```

3. Use sources under `reference/upstream-src/<version>/repository/packages/`.

To fetch another version: `./scripts/fetch-upstream-better-auth.sh 1.7.0-beta.2`
