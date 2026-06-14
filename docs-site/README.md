<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/branding/rustauth-logo-wordmark-dark.svg" />

  <source media="(prefers-color-scheme: light)" srcset="public/branding/rustauth-logo-wordmark-light.svg" />

  <img alt="RustAuth" src="public/branding/rustauth-logo-wordmark-dark.svg" width="280" />
</picture>

### Website & Docs

The main website and documentation for [rustauth.dev](https://rustauth.dev)

[![Website](https://img.shields.io/badge/better--auth.com-000?style=flat\&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNDUiIHZpZXdCb3g9IjAgMCA2MCA0NSIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAgMEgxNVYxNUgzMFYzMEgxNVY0NUgwVjMwVjE1VjBaTTQ1IDMwVjE1SDMwVjBINDVINjBWMTVWMzBWNDVINDVIMzBWMzBINDVaIiBmaWxsPSJ3aGl0ZSIvPjwvc3ZnPg==\&logoColor=white)](https://rustauth.dev)
[![GitHub Stars](https://img.shields.io/github/stars/salasebas/rustauth?style=flat\&logo=github\&label=stars\&color=24292e)](https://github.com/salasebas/rustauth)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat)](LICENSE)

***

## Quick Start

```bash
# install
pnpm install

# develop
pnpm dev
```

Open **[localhost:3000](http://localhost:3000)** to preview.

## Stack

* **Framework**: Next.js 16 (App Router, Turbopack)
* **Styling**: Tailwind CSS 4
* **Animation**: Framer Motion
* **Docs**: Fumadocs
* **Icons**: Lucide React
* **Fonts**: Geist Sans & Geist Mono

## Structure

```
├─ app/
│  ├─ page.tsx              # Home — hero + sign-in demo
│  ├─ products/             # Products page
│  ├─ blog/                 # Blog posts
│  └─ docs/[[...slug]]/     # Documentation (MDX)
│
├─ components/
│  ├─ landing/              # Marketing components
│  ├─ docs/                 # Documentation components
│  ├─ ui/                   # Shared primitives
│  └─ icons/                # Brand icons & logo
│
├─ content/                 # MDX documentation files
│
├─ lib/
│  ├─ source.ts             # Fumadocs content source
│  └─ utils.ts              # Utilities
│
└─ public/
   └─ branding/             # Logo assets (SVG + PNG)
```

## Scripts

```bash
pnpm dev          # Start dev server (Turbopack)
pnpm build        # Production build
pnpm start        # Serve production build
pnpm lint:fix     # Lint & auto-fix with Biome
pnpm sync-beta:enable  # Optional: pull upstream beta MDX into content/docs-beta
```

Beta docs sync is **off by default**. `content/docs-beta` stays empty unless you run `pnpm sync-beta:enable` (`BETA_DOCS_ENABLE=1`).
