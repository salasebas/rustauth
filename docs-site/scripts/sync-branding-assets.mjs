import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const brandingDir = path.join(
	path.dirname(fileURLToPath(import.meta.url)),
	"../public/branding",
);

const { logoAssets } = await import("../lib/branding/rustauth-mark.ts");

const files = {
	"rustauth-logo-dark.svg": logoAssets.darkSvg,
	"rustauth-logo-light.svg": logoAssets.whiteSvg,
	"rustauth-logo-wordmark-dark.svg": logoAssets.darkWordmark,
	"rustauth-logo-wordmark-light.svg": logoAssets.whiteWordmark,
};

for (const [name, contents] of Object.entries(files)) {
	fs.writeFileSync(path.join(brandingDir, name), `${contents.trim()}\n`);
}

console.log(`Wrote ${Object.keys(files).length} branding SVG files.`);
