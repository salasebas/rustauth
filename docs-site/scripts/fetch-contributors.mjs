import { execSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const BOT_LOGIN_EXACT = new Set(
	[
		"cursoragent",
		"cursorbot",
		"dependabot",
		"dependabot-preview",
		"renovate",
		"renovate-bot",
		"github-actions",
		"github-actions[bot]",
		"claude-code",
		"claude",
		"openai",
		"copilot",
	].map((s) => s.toLowerCase()),
);

const BOT_LOGIN_PATTERNS = [
	/\[bot\]$/i,
	/-bot$/i,
	/^cursor/i,
	/^github-actions/i,
	/^claude[-_]?code/i,
	/^openai/i,
	/^copilot/i,
	/dependabot/i,
	/renovate/i,
];

function isBotContributor(login, type) {
	if (type === "Bot") return true;
	const normalized = login.toLowerCase();
	if (BOT_LOGIN_EXACT.has(normalized)) return true;
	return BOT_LOGIN_PATTERNS.some((pattern) => pattern.test(login));
}

const raw = execSync(
	"gh api repos/salasebas/rustauth/contributors --paginate",
	{ encoding: "utf-8" },
);
const data = JSON.parse(raw);
const filtered = data
	.filter((c) => !isBotContributor(c.login, c.type))
	.map((c) => ({
		login: c.login,
		avatar_url: c.avatar_url,
		html_url: c.html_url,
	}));

writeFileSync("lib/contributors-data.json", JSON.stringify(filtered, null, 2));
console.log(`${filtered.length} contributors saved (${data.length - filtered.length} bots filtered)`);
