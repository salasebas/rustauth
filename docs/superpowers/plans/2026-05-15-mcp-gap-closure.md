# MCP Plugin Robustness Gap Closure Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close MCP plugin robustness gaps against Better Auth upstream behavior for OAuth/OIDC flows.

**Architecture:** Keep MCP code modular under `crates/openauth-plugins/src/mcp/`, with endpoint-specific files and test modules under `crates/openauth-plugins/tests/mcp/`. Preserve HS256 signing with `context.secret` and expose honest JWKS metadata without leaking symmetric keys.

**Tech Stack:** Rust, OpenAuth async plugin endpoints/hooks, MemoryAdapter tests, `http`, `serde_json`, `url`, `base64`, `subtle`.

---

## Checklist

- [x] Implement upstream-style consent JSON `redirectURI`, code rotation, session/expiry validation.
- [x] Harden token exchange: code consumption ordering, PKCE for public clients, Basic auth tests.
- [x] Add minimal `/mcp/userinfo` and `/mcp/jwks`.
- [x] Add scope-gated profile/email claims in ID token and userinfo.
- [x] Validate dynamic registration redirect URIs.
- [x] Robustly parse multiple `Set-Cookie` headers in login resume.
- [x] Expand MCP client helper wrapper, auth headers, CORS and discovery cache tests.
- [x] Split new MCP tests by module to keep files under roughly 600 lines.
- [x] Run final verification: fmt, MCP tests, package tests, clippy.
