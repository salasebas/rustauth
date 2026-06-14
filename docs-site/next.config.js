import { createMDX } from "fumadocs-mdx/next";

/** @type {import('next').NextConfig} */
const nextConfig = {
	experimental: {
		optimizePackageImports: [
			"lucide-react",
			"framer-motion",
			"@radix-ui/react-tabs",
			"@radix-ui/react-scroll-area",
			"@radix-ui/react-popover",
			"@radix-ui/react-select",
			"@radix-ui/react-checkbox",
		],
	},
	images: {
		remotePatterns: [
			{
				protocol: "https",
				hostname: "**",
			},
			{
				protocol: "http",
				hostname: "**",
			},
		],
	},
	async redirects() {
		return [
			{
				source: "/docs",
				destination: "/docs/introduction",
				permanent: false,
			},
			{
				source: "/legal/:path*",
				destination: "/docs/introduction",
				permanent: false,
			},
			{
				source: "/terms",
				destination: "/docs/introduction",
				permanent: false,
			},
			{
				source: "/privacy",
				destination: "/docs/introduction",
				permanent: false,
			},
			// Legacy query string based redirects
			{
				source: "/products",
				has: [{ type: "query", key: "tab", value: "framework" }],
				destination: "/products/framework",
				permanent: true,
			},
			{
				source: "/products",
				has: [{ type: "query", key: "tab", value: "infrastructure" }],
				destination: "/products/infrastructure",
				permanent: true,
			},
			{
				source: "/docs/agent-tools/ask-ai",
				destination: "/docs/ai-resources",
				permanent: true,
			},
			{
				source: "/docs/agent-tools/llms-txt",
				destination: "/llms.txt",
				permanent: true,
			},
			{
				source: "/docs/agent-tools/:path*",
				destination: "/docs/ai-resources/:path*",
				permanent: true,
			},
			{
				source: "/docs/concepts/client",
				destination: "/docs/concepts/api",
				permanent: true,
			},
			{
				source: "/docs/concepts/typescript",
				destination: "/docs/concepts/api",
				permanent: true,
			},
			{
				source:
					"/docs/integrations/:path(astro|react-router|next|nuxt|electron|svelte-kit|solid-start|tanstack|hono|fastify|encore|express|elysia|nitro|nestjs|convex|expo|lynx|waku)",
				destination: "/docs/integrations/axum",
				permanent: false,
			},
			{
				source: "/docs/examples/:path*",
				destination: "/docs/integrations/axum",
				permanent: true,
			},
			{
				source:
					"/docs/adapters/:path(drizzle|prisma|mssql|community-adapters|other-relational-databases)",
				destination: "/docs/adapters/sqlx",
				permanent: true,
			},
			{
				source: "/docs/plugins/oidc-provider",
				destination: "/docs/plugins/oauth-provider",
				permanent: true,
			},
			{
				source:
					"/docs/plugins/:path(agent-auth|autumn|creem|dodopayments|dub|chargebee|polar|test-utils|community-plugins|mcp)",
				destination: "/docs/plugins/stripe",
				permanent: true,
			},
			{
				source: "/docs/reference/resources",
				destination: "/docs/reference/contributing",
				permanent: true,
			},
			{
				source: "/docs/ai-resources/mcp",
				destination: "/docs/ai-resources",
				permanent: true,
			},
			{
				source: "/docs/ai-resources/skills",
				destination: "/docs/ai-resources",
				permanent: true,
			},
		];
	},
};

const withMDX = createMDX({
	contentDirBasePath: "/content/docs",
});
export default withMDX(nextConfig);
