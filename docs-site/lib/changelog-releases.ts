export interface ChangelogRelease {
	tag: string;
	title: string;
	content: string;
	date: string;
	url: string;
}

const UNRELEASED_URL =
	"https://github.com/salasebas/rustauth/blob/main/CHANGELOG.md#unreleased";
const DETAILS_URL =
	"https://github.com/salasebas/rustauth/blob/main/CHANGELOG.md#020---2026-06-14";

export const changelogReleases: ChangelogRelease[] = [
	{
		tag: "Unreleased",
		title: "Unreleased — Actix Web and CLI init (planned 0.3.0)",
		date: "2026-06-15",
		url: UNRELEASED_URL,
		content: `Changes on \`main\` not yet published to crates.io. The next release will likely be **0.3.0** because \`rustauth init\` now requires an explicit framework flag.

### Added

- **\`rustauth-actix-web\`** — Actix Web adapter (\`RustAuthActixWebExt\`), parity tests, docs-site guide, and \`examples/actix-web-minimal\`.
- **CLI** — \`rustauth init --framework actix-web\`, Actix workspace detection, and telemetry support.

### Changed

- **Breaking:** \`rustauth init\` requires \`--framework axum\` or \`--framework actix-web\` (no implicit default).

[Full changelog →](${UNRELEASED_URL})`,
	},
	{
		tag: "v0.2.0",
		title: "0.2.0 — initial public working release",
		date: "2026-06-14",
		url: DETAILS_URL,
		content: `First public release of **RustAuth** under the \`rustauth\` / \`rustauth-*\` crate namespace.

### Added

- Core auth server (\`rustauth\`, \`rustauth-core\`): sessions, cookies, rate limits, opt-in email/password, plugins, hooks, and Better Auth–shaped HTTP JSON.
- Axum integration (\`rustauth-axum\`), CLI (\`rustauth-cli\`), and \`rustauth.toml\` migration workflow.
- Official plugins (\`rustauth-plugins\`): admin, organization, JWT, API keys, magic link, email OTP, two-factor, SIWE, CAPTCHA, and more.
- Enterprise identity: OAuth client (\`rustauth-oauth\`), social providers, OAuth/OIDC provider, OIDC RP, SAML, SSO, SCIM, passkeys, Stripe, i18n, telemetry.
- Storage adapters: SQLx, tokio-postgres, deadpool-postgres, Redis, Fred.

[Full release notes →](${DETAILS_URL})`,
	},
];

export const EXPANDABLE_LINE_THRESHOLD = 15;

export function isExpandableRelease(content: string): boolean {
	const lineCount = content
		.split("\n")
		.filter((line) => line.trim().length > 0).length;
	return lineCount > EXPANDABLE_LINE_THRESHOLD;
}

export function formatReleaseDate(isoDate: string): string {
	return new Date(isoDate).toLocaleDateString("en-US", {
		year: "numeric",
		month: "short",
		day: "numeric",
	});
}
