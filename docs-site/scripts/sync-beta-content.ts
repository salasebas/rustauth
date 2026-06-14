import { execFileSync } from "node:child_process";
import {
	cpSync,
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";

const BRANCH = process.env.BETA_DOCS_BRANCH ?? "next";
const REPO =
	process.env.BETA_DOCS_REPO ??
	"https://github.com/better-auth/better-auth.git";
const REMOTE_PATH = "docs/content/docs";
const DEST = "content/docs-beta";
const TMP = ".beta-sync-tmp";

/** Beta docs are opt-in only. Default dev/build use local `content/docs` only. */
const BETA_ENABLED = process.env.BETA_DOCS_ENABLE === "1";

function cleanBetaDest() {
	const keep = join(DEST, ".gitkeep");
	let gitkeep = "";
	if (existsSync(keep)) {
		gitkeep = readFileSync(keep, "utf8");
	}
	rmSync(DEST, { recursive: true, force: true });
	mkdirSync(DEST, { recursive: true });
	writeFileSync(join(DEST, ".gitkeep"), gitkeep || "");
}

if (!BETA_ENABLED) {
	console.log(
		"[sync-beta] disabled (set BETA_DOCS_ENABLE=1 to sync upstream beta docs)",
	);
	cleanBetaDest();
	process.exit(0);
}

function git(args: string[], cwd?: string) {
	execFileSync("git", args, { stdio: "inherit", cwd });
}

console.log(`[sync-beta] ${BRANCH}:${REMOTE_PATH} → ${DEST}`);

try {
	rmSync(TMP, { recursive: true, force: true });

	// Sparse + blobless shallow clone fetches only the target directory.
	git([
		"clone",
		"--depth=1",
		`--branch=${BRANCH}`,
		"--filter=blob:none",
		"--sparse",
		REPO,
		TMP,
	]);
	git(["-C", TMP, "sparse-checkout", "set", REMOTE_PATH]);

	const srcPath = join(TMP, REMOTE_PATH);
	if (!existsSync(srcPath)) {
		throw new Error(`Source path not found after sparse checkout: ${srcPath}`);
	}

	rmSync(DEST, { recursive: true, force: true });
	cpSync(srcPath, DEST, { recursive: true });
	// Preserve the tracked .gitkeep so fumadocs-mdx can find the collection
	// on a fresh clone before this script has run.
	writeFileSync(join(DEST, ".gitkeep"), "");

	console.log("[sync-beta] done");
} finally {
	rmSync(TMP, { recursive: true, force: true });
}
