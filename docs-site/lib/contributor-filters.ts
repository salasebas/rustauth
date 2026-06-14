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

export function isBotContributor(login: string, type?: string): boolean {
	if (type === "Bot") return true;
	const normalized = login.toLowerCase();
	if (BOT_LOGIN_EXACT.has(normalized)) return true;
	return BOT_LOGIN_PATTERNS.some((pattern) => pattern.test(login));
}
