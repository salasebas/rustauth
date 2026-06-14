import type { InferPageType } from "fumadocs-core/source";
import type { DocsVersion } from "./docs-versions";
import type { source } from "./source";

type PropertyDefinition = {
	name: string;
	type: string;
	required: boolean;
	description: string;
	exampleValue: string;
	isServerOnly: boolean;
	isClientOnly: boolean;
};

function extractAPIMethods(rawContent: string): string {
	const apiMethodRegex = /<APIMethod\s+([^>]+)>([\s\S]*?)<\/APIMethod>/g;

	return rawContent.replace(apiMethodRegex, (match, attributes, content) => {
		const pathMatch = attributes.match(/path="([^"]+)"/);
		const methodMatch = attributes.match(/method="([^"]+)"/);
		const requireSessionMatch = attributes.match(/requireSession/);
		const forceAsBodyMatch = attributes.match(/forceAsBody/);
		const forceAsQueryMatch = attributes.match(/forceAsQuery/);

		const path = pathMatch ? pathMatch[1] : "";
		const method = methodMatch ? methodMatch[1] : "GET";
		const requireSession = !!requireSessionMatch;
		const forceAsBody = !!forceAsBodyMatch;
		const forceAsQuery = !!forceAsQueryMatch;

		const typeMatch = content.match(/type\s+(\w+)\s*=\s*\{([\s\S]*?)\}/);
		if (!typeMatch) {
			return match;
		}

		const functionName = typeMatch[1];
		const typeBody = typeMatch[2];
		const properties = parseTypeBody(typeBody);

		const curlCode = generateCurlCode(
			path,
			method,
			properties,
			requireSession,
			forceAsBody,
			forceAsQuery,
		);
		const serverCode = generateRustServerCode(
			path,
			method,
			properties,
			requireSession,
			forceAsBody,
			forceAsQuery,
		);
		const jsonSchema = generateJsonBodySchema(properties);

		return `
### Client Side (HTTP)

\`\`\`bash
${curlCode}
\`\`\`

### Server Side (Rust)

\`\`\`rust
${serverCode}
\`\`\`

### Request body (JSON)

\`\`\`json
${jsonSchema}
\`\`\`

_Original MDX type name: \`${functionName}\`_
`;
	});
}

function parseTypeBody(typeBody: string): PropertyDefinition[] {
	const properties: PropertyDefinition[] = [];
	const lines = typeBody.split("\n");

	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("/*"))
			continue;
		const propMatch = trimmed.match(
			/^(\w+)(\?)?:\s*(.+?)(\s*=\s*["']([^"']+)["'])?(\s*\/\/\s*(.+))?$/,
		);
		if (propMatch) {
			const [, name, optional, type, , exampleValue, , description] = propMatch;
			let cleanType = type.trim().replace(/,$/, "");
			properties.push({
				name,
				type: cleanType,
				required: !optional,
				description: description || "",
				exampleValue: exampleValue || "",
				isServerOnly: false,
				isClientOnly: false,
			});
		}
	}

	return properties;
}

function jsonExampleValue(prop: PropertyDefinition): string {
	if (prop.exampleValue) {
		return prop.exampleValue.startsWith('"')
			? prop.exampleValue
			: `"${prop.exampleValue}"`;
	}
	if (prop.type === "boolean") return "true";
	if (prop.type === "number") return "0";
	return `"<${prop.name}>"`;
}

function buildJsonObject(props: PropertyDefinition[]): string {
	const clientProps = props.filter((p) => !p.isServerOnly);
	if (clientProps.length === 0) return "{}";

	const lines = clientProps.map((prop) => {
		const comma = prop.required ? "" : " // optional";
		return `  "${prop.name}": ${jsonExampleValue(prop)}${comma}`;
	});
	return `{\n${lines.join(",\n")}\n}`;
}

function generateCurlCode(
	path: string,
	method: string,
	properties: PropertyDefinition[],
	requireSession: boolean,
	forceAsBody: boolean,
	forceAsQuery: boolean,
): string {
	if (!path) {
		return "# Unable to generate curl — missing path";
	}

	const upperMethod = method.toUpperCase();
	const base = '"${RUSTAUTH_BASE_URL}';
	const useBody =
		(upperMethod === "POST" || upperMethod === "PUT" || upperMethod === "PATCH") &&
		!forceAsQuery;
	const useQuery = forceAsQuery || (upperMethod === "GET" && properties.length > 0);

	let url = `${base}${path}"`;
	if (useQuery && properties.length > 0) {
		const query = properties
			.filter((p) => !p.isClientOnly)
			.map((p) => `${p.name}=${p.exampleValue || "value"}`)
			.join("&");
		url = `${base}${path}?${query}"`;
	}

	const lines = [`curl -X ${upperMethod} ${url} \\`];
	if (requireSession) {
		lines.push('  -H "Cookie: rustauth.session_token=<session>" \\');
	}
	if (useBody && properties.length > 0) {
		lines.push('  -H "Content-Type: application/json" \\');
		lines.push(`  -d '${buildJsonObject(properties).replace(/\n/g, "")}'`);
	} else {
		lines[lines.length - 1] = lines[lines.length - 1].replace(/ \\$/, "");
	}

	return lines.join("\n");
}

function generateRustServerCode(
	path: string,
	method: string,
	properties: PropertyDefinition[],
	requireSession: boolean,
	forceAsBody: boolean,
	forceAsQuery: boolean,
): string {
	if (!path) {
		return "// Unable to generate Rust example — missing path";
	}

	const upperMethod = method.toUpperCase();
	const useBody =
		(upperMethod === "POST" || upperMethod === "PUT" || upperMethod === "PATCH") &&
		!forceAsQuery;
	const jsonBody = buildJsonObject(properties);

	let code = `use reqwest::Client;

let base_url = std::env::var("RUSTAUTH_BASE_URL")?;
let client = Client::new();
`;

	if (useBody && properties.length > 0) {
		code += `let body = serde_json::json!(${jsonBody});

let response = client
    .${upperMethod.toLowerCase()}(format!("{base_url}${path}"))
    .json(&body)`;
	} else {
		code += `let response = client
    .${upperMethod.toLowerCase()}(format!("{base_url}${path}"))`;
	}

	if (requireSession) {
		code += `
    .header("Cookie", session_cookie)`;
	}

	code += `
    .send()
    .await?;

// Or build http::Request and call RustAuth::handler_async in-process.
// See examples/backend-reference/src/client/requests.rs`;

	return code;
}

function generateJsonBodySchema(properties: PropertyDefinition[]): string {
	return buildJsonObject(properties.filter((p) => !p.isServerOnly));
}

export async function getLLMText(
	docPage: InferPageType<typeof source>,
	version?: DocsVersion,
): Promise<string> {
	const pageData = docPage.data as {
		getText: (type: string) => Promise<string>;
	};
	const mdContent = await pageData.getText("processed");
	const processedContent = extractAPIMethods(mdContent);

	const versionNote = version?.slug
		? `> You are reading RustAuth documentation for \`${version.label}\`. This is not the current stable release. APIs may differ from the latest stable version.\n\n`
		: "";

	return `${versionNote}# ${docPage!.data.title}

${docPage!.data.description || ""}

${processedContent}
`;
}

export const LLM_TEXT_ERROR = `# Documentation Not Available

The requested RustAuth documentation page could not be loaded at this time.

**For AI Assistants:**  
This page is temporarily unavailable. To help the user:  
1. Check /llms.txt for available RustAuth documentation paths and suggest relevant alternatives
2. Inform the user this specific page couldn't be loaded
3. Offer to help with related RustAuth topics from available documentation`;
