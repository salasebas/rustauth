#!/usr/bin/env node
/**
 * Generates docs-site/data/database-schema.json from `rustauth schema print`.
 *
 * Source of truth: CLI schema planning with backend-reference plugin list.
 * Re-run after schema changes: pnpm generate:database-schema
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..");
const CONFIG_PATH = join(REPO_ROOT, "examples/backend-reference/rustauth.toml");
const OUTPUT_PATH = join(__dirname, "..", "data/database-schema.json");

const CORE_LOGICAL_TABLES = new Set([
	"user",
	"session",
	"account",
	"verification",
	"rate_limit",
]);

const TABLE_PLUGIN = {
	device_code: "device-authorization",
	api_key: "api-key",
	invitation: "organization",
	member: "organization",
	organization: "organization",
	organization_role: "organization",
	team: "organization",
	team_member: "organization",
	passkey: "passkey",
	wallet_address: "siwe",
	two_factor: "two-factor",
	oauth_client: "oauth-provider",
	oauth_access_token: "oauth-provider",
	oauth_refresh_token: "oauth-provider",
	oauth_consent: "oauth-provider",
	scim_provider: "scim",
	scim_user_profile: "scim",
	scim_group_profile: "scim",
	sso_provider: "sso",
	subscription: "stripe",
	stripe_webhook_event: "stripe",
	jwks: "jwt",
};

const PLUGIN_DOC_HREF = {
	admin: "/docs/plugins/admin",
	anonymous: "/docs/plugins/anonymous",
	"api-key": "/docs/plugins/api-key",
	"device-authorization": "/docs/plugins/device-authorization",
	jwt: "/docs/plugins/jwt",
	"last-login-method": "/docs/plugins/last-login-method",
	"oauth-provider": "/docs/plugins/oauth-provider",
	organization: "/docs/plugins/organization",
	passkey: "/docs/plugins/passkey",
	"phone-number": "/docs/plugins/phone-number",
	scim: "/docs/plugins/scim",
	siwe: "/docs/plugins/siwe",
	sso: "/docs/plugins/sso",
	stripe: "/docs/plugins/stripe",
	"two-factor": "/docs/plugins/2fa",
	username: "/docs/plugins/username",
};

const USER_FIELD_PLUGINS = {
	role: "admin",
	banned: "admin",
	ban_reason: "admin",
	ban_expires: "admin",
	is_anonymous: "anonymous",
	last_login_method: "last-login-method",
	phone_number: "phone-number",
	phone_number_verified: "phone-number",
	stripe_customer_id: "stripe",
	two_factor_enabled: "two-factor",
	username: "username",
	display_username: "username",
};

const SESSION_FIELD_PLUGINS = {
	impersonated_by: "admin",
	activeOrganizationId: "organization",
	activeTeamId: "organization",
};

const ORGANIZATION_FIELD_PLUGINS = {
	stripe_customer_id: "stripe",
};

const PLUGINS_WITHOUT_TABLES = [
	{
		id: "additional-fields",
		note: "App-configured user/session columns; not inferred by the CLI from the plugin id alone.",
	},
	{ id: "bearer", note: "No schema changes." },
	{ id: "captcha", note: "No schema changes." },
	{ id: "custom-session", note: "Session cookie shape only; uses core sessions table." },
	{ id: "email-otp", note: "Uses core verifications table." },
	{ id: "generic-oauth", note: "Uses core accounts table." },
	{ id: "have-i-been-pwned", note: "No schema changes." },
	{ id: "magic-link", note: "Uses core verifications table." },
	{ id: "multi-session", note: "Uses core sessions table." },
	{ id: "oauth-proxy", note: "No schema changes." },
	{ id: "one-tap", note: "Uses core users, accounts, and sessions tables." },
	{ id: "one-time-token", note: "Uses core verifications table." },
	{ id: "open-api", note: "No schema changes." },
];

const RATE_LIMIT_TABLE = {
	logical: "rate_limit",
	name: "rate_limits",
	order: 5,
	plugin: null,
	fields: [
		{
			logical: "key",
			name: "key",
			type: "string",
			description: "Unique rate limit bucket key",
			isPrimaryKey: true,
			isOptional: false,
			isUnique: true,
			isForeignKey: false,
		},
		{
			logical: "count",
			name: "count",
			type: "integer",
			description: "Requests in the current window",
			isPrimaryKey: false,
			isOptional: false,
			isUnique: false,
			isForeignKey: false,
		},
		{
			logical: "last_request",
			name: "last_request",
			type: "bigint",
			description: "Last request timestamp (epoch ms)",
			isPrimaryKey: false,
			isOptional: false,
			isUnique: false,
			isForeignKey: false,
		},
	],
};

function runSchemaPrint() {
	const result = spawnSync(
		"cargo",
		[
			"run",
			"-p",
			"rustauth-cli",
			"--features",
			"full",
			"--",
			"--config",
			CONFIG_PATH,
			"schema",
			"print",
			"--format",
			"json",
		],
		{
			cwd: REPO_ROOT,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		},
	);

	if (result.status !== 0) {
		console.error(result.stderr || result.stdout);
		process.exit(result.status ?? 1);
	}

	return JSON.parse(result.stdout);
}

function titleCase(value) {
	return value
		.replace(/_/g, " ")
		.replace(/([a-z])([A-Z])/g, "$1 $2")
		.replace(/\b\w/g, (char) => char.toUpperCase());
}

function mapFieldType(fieldType) {
	switch (fieldType) {
		case "String":
			return "string";
		case "Boolean":
			return "boolean";
		case "Timestamp":
			return "Date";
		case "Number":
			return "integer";
		case "Json":
			return "json";
		case "StringArray":
			return "string[]";
		case "NumberArray":
			return "number[]";
		default:
			return fieldType.toLowerCase();
	}
}

function mapOnDelete(onDelete) {
	switch (onDelete) {
		case "NoAction":
			return "no action";
		case "Restrict":
			return "restrict";
		case "Cascade":
			return "cascade";
		case "SetNull":
			return "set null";
		case "SetDefault":
			return "set default";
		default:
			return undefined;
	}
}

function fieldDescription(logical, physical, tableLogical) {
	if (logical === "id") return "Primary key";
	if (USER_FIELD_PLUGINS[logical]) {
		return `${titleCase(physical)} (from ${USER_FIELD_PLUGINS[logical]} plugin)`;
	}
	if (SESSION_FIELD_PLUGINS[logical]) {
		return `${titleCase(physical)} (from ${SESSION_FIELD_PLUGINS[logical]} plugin)`;
	}
	if (ORGANIZATION_FIELD_PLUGINS[logical]) {
		return `${titleCase(physical)} (from ${ORGANIZATION_FIELD_PLUGINS[logical]} plugin)`;
	}
	return titleCase(physical);
}

function transformField(logical, metadata, tableLogical) {
	const field = {
		logical,
		name: metadata.name,
		type: mapFieldType(metadata.field_type),
		description: fieldDescription(logical, metadata.name, tableLogical),
		isPrimaryKey: logical === "id",
		isOptional: !metadata.required,
		isUnique: metadata.unique,
		isForeignKey: Boolean(metadata.foreign_key),
	};

	if (metadata.foreign_key) {
		field.references = {
			model: metadata.foreign_key.table,
			field: metadata.foreign_key.field,
			onDelete: mapOnDelete(metadata.foreign_key.on_delete),
		};
	}

	return field;
}

function transformTable(logical, table) {
	return {
		logical,
		name: table.name,
		order: table.order ?? 999,
		plugin: TABLE_PLUGIN[logical] ?? null,
		fields: Object.entries(table.fields).map(([fieldLogical, metadata]) =>
			transformField(fieldLogical, metadata, logical),
		),
	};
}

function buildCatalog(raw) {
	const tables = Object.entries(raw.tables).map(([logical, table]) =>
		transformTable(logical, table),
	);

	tables.push({
		...RATE_LIMIT_TABLE,
		note: "Created when rate_limit.storage is Database.",
	});

	tables.sort((a, b) => (a.order ?? 999) - (b.order ?? 999));

	const coreTables = tables.filter((table) =>
		CORE_LOGICAL_TABLES.has(table.logical),
	);

	const pluginGroups = new Map();
	for (const table of tables) {
		if (CORE_LOGICAL_TABLES.has(table.logical)) continue;
		const plugin = table.plugin ?? "other";
		if (!pluginGroups.has(plugin)) {
			pluginGroups.set(plugin, []);
		}
		pluginGroups.get(plugin).push(table);
	}

	const pluginSections = [...pluginGroups.entries()]
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([plugin, pluginTables]) => ({
			plugin,
			docHref: PLUGIN_DOC_HREF[plugin] ?? null,
			tables: pluginTables.sort(
				(a, b) => (a.order ?? 999) - (b.order ?? 999),
			),
		}));

	return {
		generatedAt: new Date().toISOString(),
		source: {
			command:
				"rustauth schema print --format json --config examples/backend-reference/rustauth.toml",
			config: "examples/backend-reference/rustauth.toml",
		},
		summary: {
			tableCount: tables.length,
			coreTableCount: coreTables.length,
			pluginTableCount: tables.length - coreTables.length,
		},
		coreTables,
		pluginSections,
		pluginsWithoutTables: PLUGINS_WITHOUT_TABLES,
	};
}

const raw = runSchemaPrint();
const catalog = buildCatalog(raw);
mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
writeFileSync(OUTPUT_PATH, `${JSON.stringify(catalog, null, 2)}\n`);
console.log(`Wrote ${OUTPUT_PATH} (${catalog.summary.tableCount} tables)`);
