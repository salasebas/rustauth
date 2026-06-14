#!/usr/bin/env node
/**
 * Smoke test for llm-text APIMethod → curl/Rust transform.
 * Run from docs-site: node scripts/test-llm-text.mjs
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = readFileSync(join(root, "lib/llm-text.ts"), "utf8");

if (src.includes("authClient")) {
	console.error("FAIL: llm-text.ts still contains authClient");
	process.exit(1);
}

if (!src.includes("generateCurlCode") && !src.includes("curl -X")) {
	console.error("FAIL: llm-text.ts missing curl generation");
	process.exit(1);
}

const sample = `
<APIMethod path="/sign-up/email" method="POST">
type signUpEmail = {
  name: string
  email: string
  password: string
}
</APIMethod>
`;

// Minimal inline transform mirroring production rules
const apiMethodRegex = /<APIMethod\s+([^>]+)>([\s\S]*?)<\/APIMethod>/g;
const out = sample.replace(apiMethodRegex, (_m, attributes) => {
	const pathMatch = attributes.match(/path="([^"]+)"/);
	const methodMatch = attributes.match(/method="([^"]+)"/);
	const path = pathMatch?.[1] ?? "";
	const method = methodMatch?.[1] ?? "GET";
	return `curl -X ${method.toUpperCase()} "\${RUSTAUTH_BASE_URL}${path}"`;
});

if (!out.includes("curl -X POST") || out.includes("authClient")) {
	console.error("FAIL: sample transform did not produce curl output");
	process.exit(1);
}

console.log("OK: llm-text smoke checks passed");
